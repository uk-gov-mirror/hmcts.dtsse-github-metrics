import "server-only";
import { collectionState } from "../store/collection-state.ts";
import { WEEK_OPTIONS } from "./spans.ts";

/**
 * The built reports the dashboard is served from, and the one stamp that invalidates them.
 *
 * Every page reads the estate through `repositoryRows`, and three of them read it two or three times per render
 * — `/repositories` asks for the overview and the rows, `/teams` for the overview and the cards. So the estate
 * is built once and held, and the interesting question is only how long "once" lasts.
 *
 * ONE ENTRY PER SPAN, NOT ONE IN TOTAL. Holding a single entry keyed on span meant a reader switching from four
 * weeks to twelve evicted the four-week build, and the next reader of four weeks paid for it again — on an
 * estate five spans wide and a dashboard nobody reads alone, the held entry was being thrown away by the
 * reader who arrived next rather than by anything changing. All five spans fit because a built report is rows
 * of counts and labels rather than the facts behind them.
 *
 * INVALIDATED BY `collection_state.revision`, NEVER BY A TIMER. The data changes exactly when a collection
 * lands, which the collector announces by bumping that revision — so a built report is correct until the
 * revision moves and no sooner, and a clock could only ever be wrong in one of two directions: rebuilding a
 * report that had not changed, or serving one that had. Both collectors bump it, `collect` at 15:00 and
 * `collect-org` at 14:00, which is why the graph's half invalidates the report too.
 *
 * The MAP IS PRUNED to the current revision on every miss. Without that, a week of daily collections would
 * leave a week of superseded builds in a process that never restarts.
 */

interface Entry {
  revision: string;
  /**
   * The build, held as a PROMISE rather than as its result.
   *
   * Two concurrent readers of a cold span then share one build instead of racing to do it twice, which on one
   * CPU is the difference between one 1.2-second build and two competing for the same core. It is also what
   * makes the warmer safe to run beside live traffic: a reader arriving mid-warm awaits the warmer's build
   * rather than starting a second.
   */
  built: Promise<unknown[]>;
}

/**
 * The held builds, on `globalThis` rather than in this module's scope.
 *
 * A `globalThis` singleton for the reason `store/prisma.ts` is one, and then for a second reason that is
 * specific to this being read from two places. Next bundles the report layer into a SEPARATE CHUNK per entry
 * point: the pages get an `ssr/` copy and `instrumentation.ts` gets its own, so a module-scoped Map gives the
 * warmer one cache and every page another. Measured before this: the warmer logged five warmed spans and the
 * first request for each of them still took 5 to 15 seconds, because the pages were reading an empty Map.
 *
 * The same seam also survives a development reload, which is what the Prisma singleton is there for.
 */
const globalForReports = globalThis as unknown as { builtReports?: Map<string, Entry> };

globalForReports.builtReports ??= new Map<string, Entry>();

const entries: Map<string, Entry> = globalForReports.builtReports;

/**
 * What a held build IS, so two reports over one span cannot be served as each other.
 *
 * The key carried the estate and the span only until 2026-09-15, which was correct while `repositoryRows` was the
 * one thing built. A second report over the same span would have collided with it and been returned in its place.
 *
 * ONE MEMBER, because one entry holds every report a span produces. It named four while the rows, the contributors
 * and the two activity tables were four builds; they are one `EstateReports` now, so three of the four kinds were
 * spellings nothing could pass. The type stays because the key does: a second thing held per span has to name
 * itself here before it can be stored, rather than silently sharing this one's entry.
 */
export type ReportKind = "repositories";

/** The key one build is held under, which names what it is as well as the estate and the span. */
function keyOf(organization: string, kind: ReportKind, weeks: number): string {
  return `${organization}|${kind}|${weeks}`;
}

/** The revision every entry is compared against, as a string so a cold database has a value too. */
async function currentRevision(): Promise<string> {
  const state = await collectionState();
  return state === undefined ? "none" : String(state.revision);
}

/** Forgets every built report, so a test or a reload starts cold. */
export function forgetBuiltReports(): void {
  entries.clear();
}

/** How many spans are held, for the warmer's log and for a test to assert against. */
export function builtSpanCount(): number {
  return entries.size;
}

/**
 * One span's built report: the held one where the collection has not moved, or a fresh build.
 *
 * A REJECTION IS NOT CACHED. A transient database error during a build would otherwise be served as this
 * span's answer for the life of the process, which on a pod that restarts only when Flux rolls it means until
 * somebody notices. The entry is dropped and the next reader builds again.
 *
 * A span outside `WEEK_OPTIONS` is built and NOT held. The spans come off a query string, so caching every
 * value one could carry is an unbounded map keyed by whatever a reader types; refusing to hold it costs a
 * rebuild on a span no page links to and keeps the map the size of the selector.
 */
export async function builtReport<RowT>(organization: string, weeks: number, build: () => Promise<RowT[]>, kind: ReportKind = "repositories"): Promise<RowT[]> {
  const revision = await currentRevision();
  const key = keyOf(organization, kind, weeks);
  const held = entries.get(key);
  if (held?.revision === revision) {
    // THE ONE CAST IN THIS FILE, and it is what a map keyed on `ReportKind` costs. The stored promise cannot be
    // typed as the caller's row, because what ties a key to a shape is `keyOf` and every caller reaches it through
    // this function alone. A caller asking for a kind under the wrong type is the failure this cannot catch; there
    // is one kind and one call site today, in `report/reports.ts`.
    return (await held.built) as RowT[];
  }

  const built = build().catch((error: unknown) => {
    entries.delete(key);
    throw error;
  });

  if (!WEEK_OPTIONS.includes(weeks)) {
    return await built;
  }

  // Every entry from a superseded collection describes a database that has moved on, so the landing of one
  // collection empties the cache rather than leaving each span to notice on its own next read.
  for (const [existing, entry] of entries) {
    if (entry.revision !== revision) {
      entries.delete(existing);
    }
  }
  entries.set(key, { revision, built });
  return await built;
}
