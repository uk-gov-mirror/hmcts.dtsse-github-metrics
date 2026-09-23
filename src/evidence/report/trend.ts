import type * as contract from "../../lib/types.ts";
import { botAccounts, contributorLogins, excludedAuthors, ratePercentage, reportedCohort } from "../behaviour/analysis.ts";
import { type BehaviourMetric, behaviourMetrics, Percentile } from "../behaviour/metrics.ts";
import { roundHalfEven } from "../behaviour/rounding.ts";
import { EvidenceSource, type Interval } from "../domain/coverage.ts";
import { type DistributionObservation, type Merges, ObservationStatus, type RateObservation } from "../domain/facts.ts";
import type { Configuration } from "../policy/schema.ts";
import { findMissingIntervals } from "../store/intervals.ts";
import type { ReportingWindow } from "../window/window.ts";
import { stripAbsent } from "./absent.ts";
import { contractObservation } from "./contract/observation.ts";
import type { MeasuredRow } from "./measured.ts";
import { cohortSummary } from "./repository-evidence.ts";

/**
 * Comparing one repository's windows since enablement. Ported from `metrics.trend`.
 *
 * WIRED SINCE VIBE-592, and the arithmetic below is unchanged by the wiring. What was missing was never the
 * comparison — it was the ASSEMBLY: nothing walked a repository's periods from `enablement:`, so `getTrend`
 * returned `periods: []` for every repository on the estate and the page's trend section drew its empty state
 * permanently. `builtRepositoryTrend` at the foot of this file is that walk, and `report/reports.ts` supplies it
 * with the two reads it cannot do itself.
 *
 * NOT THE SAME THING AS `lib/trend.ts`, which is the UI half: it turns the series this builds into chart rows and
 * labels. This is the REPORT half — which windows exist, what each of them observed, and what moved between them.
 *
 * PURE, LIKE EVERYTHING UNDER `report/**` BUT THE TWO MODULES THAT READ POSTGRES. The facts, the coverage
 * intervals and the reference instant are all handed in, which is what keeps this at the coverage bar the rest of
 * the report layer is held to rather than reachable only by an integration run.
 *
 * DERIVED ARITHMETIC ONLY: nothing here consults a threshold, and no result is graded or coloured. A trend says
 * what moved, and by how much; whether that is good is a question the readiness assessment answers separately.
 */

/** How a movement is expressed. */
export const DeltaBasis = {
  /** A relative change, for a count or a distribution. */
  PercentageChange: "percentage_change",
  /** An absolute difference, for a rate: never a relative percentage of a percentage. */
  PercentagePoints: "percentage_points"
} as const;

export type DeltaBasis = (typeof DeltaBasis)[keyof typeof DeltaBasis];

const BASELINE_ZERO = "the baseline is zero, so a relative change cannot be computed";

/** Says why a series compares none of its periods, quoting what the baseline itself reported. */
export function noBaselineDelta(detail: string): string {
  return `the baseline window is not comparable, so no delta was computed: ${detail}`;
}

/** Says why a window's metric values are suppressed, or `undefined` when its cohort is big enough. */
export function thinWindow(counted: number, minimum: number): string | undefined {
  if (counted >= minimum) {
    return undefined;
  }
  return `${counted} merges into the default branch, below the minimum of ${minimum}, so metric values are suppressed`;
}

/** One metric's observation beside the single number a series compares windows on. */
export interface TrendMetric {
  metric: string;
  summary: RateObservation | DistributionObservation;
  value?: number;
  percentile?: Percentile;
}

export interface TrendDelta {
  measure: string;
  basis: DeltaBasis;
  baseline: number;
  period: number;
  change?: number;
  unit?: string;
  percentile?: Percentile;
  detail?: string;
}

interface Comparison {
  basis: DeltaBasis;
  unit?: string;
  percentile?: Percentile;
}

/** How a cohort count is compared: relative change, with both absolute counts always reported. */
const COUNT: Comparison = { basis: DeltaBasis.PercentageChange };

/** How a rate is compared: in percentage points, never as a relative percentage of a percentage. */
const RATE: Comparison = { basis: DeltaBasis.PercentagePoints, unit: "percent" };

/** Whether one observation is a distribution, which is what tells the two observation shapes apart. */
function isDistribution(summary: RateObservation | DistributionObservation): summary is DistributionObservation {
  return "unit" in summary;
}

/** The value a distribution is compared at, read from the percentile the metric declares. */
function percentileValue(metric: BehaviourMetric, observation: DistributionObservation): number | undefined {
  if (metric.percentile === Percentile.Percentile75) {
    return observation.percentile75;
  }
  if (metric.percentile === Percentile.Percentile90) {
    return observation.percentile90;
  }
  return observation.median;
}

/**
 * One metric's observation beside the number a series compares windows on.
 *
 * A rate is compared as a percentage; a distribution at the FIXED PERCENTILE THE METRIC DECLARES and the
 * readiness assessment grades, read through the metric so the two cannot diverge. Either is absent where the
 * window observed no eligible sample, and a metric with no value in one of the two windows has no delta rather
 * than a delta against nothing.
 */
export function trendMetric(metric: BehaviourMetric, summary: RateObservation | DistributionObservation): TrendMetric {
  if (isDistribution(summary)) {
    const value = summary.status === ObservationStatus.Observed ? percentileValue(metric, summary) : undefined;
    return { metric: metric.identifier, summary, ...(value === undefined ? {} : { value }), percentile: metric.percentile };
  }
  const value = ratePercentage(summary);
  return { metric: metric.identifier, summary, ...(value === undefined ? {} : { value }) };
}

/** How one behaviour metric moves, from the shape of the observation itself. */
export function metricComparison(item: TrendMetric): Comparison {
  if (!isDistribution(item.summary)) {
    return RATE;
  }
  return {
    basis: DeltaBasis.PercentageChange,
    unit: item.summary.unit,
    ...(item.percentile === undefined ? {} : { percentile: item.percentile })
  };
}

/**
 * How one measure moved between the baseline and one period.
 *
 * RATES ARE SUBTRACTED AFTER BOTH ARE ROUNDED TO THE TENTH, so the reported movement is exactly the difference
 * between the two reported values rather than a third number rounded separately. A reader who subtracts the two
 * figures on the page must get the figure the page states.
 */
export function delta(measure: string, comparison: Comparison, baseline: number, period: number): TrendDelta {
  let change: number | undefined;
  let detail: string | undefined;

  if (comparison.basis === DeltaBasis.PercentagePoints) {
    change = roundHalfEven(period - baseline, 1);
  } else if (baseline === 0) {
    // A relative change against nothing is not a large movement, it is an undefined one.
    detail = BASELINE_ZERO;
  } else {
    change = roundHalfEven(((period - baseline) / baseline) * 100, 1);
  }

  return {
    measure,
    basis: comparison.basis,
    baseline,
    period,
    ...(change === undefined ? {} : { change }),
    ...(comparison.unit === undefined ? {} : { unit: comparison.unit }),
    ...(comparison.percentile === undefined ? {} : { percentile: comparison.percentile }),
    ...(detail === undefined ? {} : { detail })
  };
}

/** Compares one metric between the two windows, or reports nothing where either observed no value. */
export function metricDelta(baseline: TrendMetric | undefined, period: TrendMetric): TrendDelta | undefined {
  if (baseline?.value === undefined || period.value === undefined) {
    return undefined;
  }
  return delta(period.metric, metricComparison(period), baseline.value, period.value);
}

/** Compares every metric BOTH windows observed, and no others. */
export function metricDeltas(baseline: readonly TrendMetric[], period: readonly TrendMetric[]): TrendDelta[] {
  const observed = new Map(baseline.map((item) => [item.metric, item]));
  return period.map((item) => metricDelta(observed.get(item.metric), item)).filter((computed): computed is TrendDelta => computed !== undefined);
}

/** What one window put onto the default branch, by both routes and in total, and who put it there. */
export interface TrendThroughput {
  mergedPullRequests: number;
  directCommits: number;
  merges: number;
  /**
   * How many people landed a change in the window, counted over both routes.
   *
   * REPORTED AND NOT COMPARED. `throughputMeasures` below names the three measures a series moves on and this is
   * deliberately not one of them: a change in the number of people is a change in the team rather than in its
   * practice, and a delta on it would read as a movement in how the repository is worked.
   */
  activeContributors: number;
}

/** The measures a throughput comparison names, spelled once so deltas and rendered rows cannot disagree. */
export function throughputMeasures(throughput: TrendThroughput): [string, number][] {
  return [
    ["merged pull requests", throughput.mergedPullRequests],
    ["direct commits", throughput.directCommits],
    ["merges", throughput.merges]
  ];
}

/** Compares what the two windows put onto the default branch. */
export function throughputDeltas(baseline: TrendThroughput, period: TrendThroughput): TrendDelta[] {
  const counts = new Map(throughputMeasures(baseline));
  return throughputMeasures(period).map(([measure, value]) => delta(measure, COUNT, counts.get(measure) ?? 0, value));
}

/**
 * A SERIES CARRIES NO ALERT HISTORY, and the empty list is the honest answer rather than a placeholder.
 *
 * `alert_observations` is REQUIRED by the contract — a series either carries the history behind it or carries
 * none — and `lib/trend.ts` reads the field off the type without a guard, so it cannot be omitted. Nothing has
 * ever written an `alert_observations` row: the table exists and `collect` does not populate it, so every series
 * on the estate would report the same empty list whether it were read or not. Reading it would state a measured
 * nothing where nobody has measured, which is the one confusion this contract exists to prevent, so the read is
 * deliberately not made until something writes the rows. VIBE-592 records that gap.
 *
 * A FRESH LIST PER SERIES rather than one shared constant, for `reportedWindowOptions`' reason: the contract
 * declares a mutable array, and a caller sorting or pushing to it would be reaching into every other series.
 */
function noAlertHistory(): contract.AlertObservation[] {
  return [];
}

/** What a collection covered for one repository's two behaviour sources, in chronological order. */
export interface TrendCoverage {
  pullRequests: readonly Interval[];
  directCommits: readonly Interval[];
}

/** Everything `builtRepositoryTrend` needs and cannot read for itself. See `repositoryTrend` in `./reports.ts`. */
export interface TrendSeriesInput {
  repository: string;
  enablement: Date;
  /** The one period ending at the enablement instant, which the periods are measured against. */
  baseline: ReportingWindow;
  /** Each whole period since enablement, already cut to whatever the request asked for. */
  periods: readonly ReportingWindow[];
  /**
   * Every fact the cache held over the baseline and every period, in ONE read, before the cohort rule narrows it.
   *
   * SLICED HERE RATHER THAN QUERIED PER WINDOW. A fourteen-window series asked per window is twenty-eight
   * indexed reads and twenty-eight coverage stamps for one page section; the facts a window holds are a filter
   * over a read that already spans it. `cachePullRequestFacts` writes the `merged_at` column and the payload's
   * own copy of it from one fact, so slicing on the payload makes exactly the cut the per-window query would.
   */
  walked: Merges;
  coverage: TrendCoverage;
}

/**
 * One repository's series since enablement: the baseline, each whole period, and what moved between them.
 *
 * WHY A PERIOD CAN SAY THREE DIFFERENT THINGS, which is the absent-versus-zero rule applied per window rather
 * than per row:
 *
 *   • NOT COVERED. No collection walked this window, so the counts are ABSENT and the metrics empty. Collection
 *     fills `lookback.operational_days` — 90 days by default — and a cut of 13 periods reaches 364 days back, so
 *     the early periods of a long-enabled repository are normally in this state. A zero here would say the
 *     repository merged nothing in a month nobody looked at.
 *   • COVERED BUT THIN. The window was read and holds fewer merges than `assessment.minimum_merges`, so its
 *     counts are reported and its metric VALUES are suppressed — a rate over four merges is arithmetic rather
 *     than a pattern. `thinWindow` says so in the window's own `detail`.
 *   • COVERED AND OBSERVED. Counts and metrics both.
 *
 * NOTHING IS GRADED. The readiness policy is not consulted and no label is attached; `minimum_merges` is read as
 * the cohort size below which a rate says nothing, which is the same reason the assessment reads it.
 */
export function builtRepositoryTrend(configuration: Configuration, input: TrendSeriesInput): contract.RepositoryTrend {
  const metrics = behaviourMetrics(configuration.traceability);
  const excluded = excludedAuthors(configuration.cohort.excluded_authors);
  const bots = botAccounts(configuration.cohort.bot_accounts);
  // The declaration `measuredSources` honours for the estate row, folded on both sides for its reason: a
  // hand-typed repository name and the repository's own spelling are written by different hands.
  const declaredRead = configuration.cohort.no_direct_pushes.some((named) => named.toLowerCase() === input.repository.toLowerCase());
  const resolve = (window: ReportingWindow): ResolvedWindow => {
    const measured: MeasuredRow = {
      pullRequests: covers(window, input.coverage.pullRequests),
      directCommits: declaredRead || covers(window, input.coverage.directCommits)
    };
    return resolvedWindow(configuration, metrics, { window, measured, walked: within(input.walked, window), excluded, bots });
  };

  const baseline = resolve(input.baseline);
  const periods = input.periods.map(resolve);
  // A BASELINE THAT OBSERVED NO THROUGHPUT COMPARES NOTHING, and the series says which window let it down rather
  // than leaving every period's `deltas` empty for a reader to guess at. A baseline that was READ but is merely
  // thin still compares its counts: `metricDeltas` drops the metrics it has no baseline value for on its own.
  const comparable = baseline.throughput;

  return stripAbsent<contract.RepositoryTrend>({
    repository: input.repository,
    enablement_at: input.enablement.toISOString(),
    baseline: contractWindow(baseline),
    periods: periods.map((period, index) => ({
      ...contractWindow(period),
      // ONE-INDEXED FROM THE ENABLEMENT INSTANT, by the contract, and NOT from this array's position: a cut
      // series still names its periods the way an uncut one does, which is what `lib/trend.ts` labels `P1`
      // onwards from.
      index: index + 1,
      deltas: comparable === undefined ? [] : periodDeltas(comparable, baseline.metrics, period)
    })),
    alert_observations: noAlertHistory(),
    ...(comparable === undefined ? { delta_detail: noBaselineDelta(baseline.detail ?? NOT_READ) } : {})
  });
}

/**
 * The series for a repository with no `enablement:` date, which is not an error.
 *
 * DISTINCT FROM `trendWithoutWholePeriod` BY MORE THAN ITS PROSE. This carries no `enablement_at` at all, so a
 * reader can tell "nobody has said when this repository was enabled" from "it has not been enabled long enough
 * yet" without parsing a sentence. Both are real states of a real series rather than an error.
 */
export function trendWithoutEnablement(repository: string): contract.RepositoryTrend {
  return {
    repository,
    periods: [],
    alert_observations: noAlertHistory(),
    detail: "no enablement date is configured for this repository"
  };
}

/** The series for a repository enabled too recently for one whole period to have elapsed. */
export function trendWithoutWholePeriod(repository: string, enablement: Date, periodDays: number): contract.RepositoryTrend {
  return {
    repository,
    enablement_at: enablement.toISOString(),
    periods: [],
    alert_observations: noAlertHistory(),
    // A PARTIAL PERIOD IS NOT REPORTED, for `periodWindows`' reason: it is not comparable with a whole one, and
    // drawing it would show every newly enabled repository dipping at its right-hand edge for arithmetic alone.
    detail: `no whole period of ${periodDays} days has elapsed since ${enablement.toISOString()}, so there is nothing to compare with the baseline`
  };
}

/** What the series says when its baseline was never read, which has no `detail` of its own to quote. */
const NOT_READ = "no collection covered the baseline window";

/** One window of a series as the arithmetic sees it, before the contract's own spelling of it. */
interface ResolvedWindow {
  window: ReportingWindow;
  cohort: contract.CohortSummary;
  /** Absent where either source went unread, because a total of one measured half and one absent half is a lie. */
  throughput?: TrendThroughput;
  /** Empty where the window was unread or too thin to read a pattern from. */
  metrics: TrendMetric[];
  detail?: string;
}

interface WindowFacts {
  window: ReportingWindow;
  measured: MeasuredRow;
  walked: Merges;
  excluded: ReadonlySet<string>;
  bots: ReadonlySet<string>;
}

function resolvedWindow(configuration: Configuration, metrics: readonly BehaviourMetric[], facts: WindowFacts): ResolvedWindow {
  const reported = reportedCohort(facts.walked, facts.excluded, facts.bots);
  const merges = reported.merges;
  const cohort = cohortSummary(facts.walked, reported, facts.measured);
  const unread = unreadSources(facts.measured);
  if (unread !== undefined) {
    return { window: facts.window, cohort, metrics: [], detail: unread };
  }
  const throughput: TrendThroughput = {
    mergedPullRequests: merges.pullRequests.length,
    directCommits: merges.directCommits.length,
    merges: merges.pullRequests.length + merges.directCommits.length,
    // Off the reported cohort, so the people counted are the people whose merges the figures beside them count.
    activeContributors: contributorLogins([...merges.pullRequests, ...merges.directCommits], facts.bots).size
  };
  // Counted over BOTH ROUTES, which is how `assessment.minimum_merges` is counted: a repository doing most of
  // its work in direct commits has plenty of evidence, and counting merged pull requests alone would suppress a
  // window precisely where the bypass is worst.
  const thin = thinWindow(throughput.merges, configuration.assessment.minimum_merges);
  return {
    window: facts.window,
    cohort,
    throughput,
    metrics: thin === undefined ? metrics.map((metric) => trendMetric(metric, metric.summary(merges))) : [],
    ...(thin === undefined ? {} : { detail: thin })
  };
}

/** Says which cached source does not reach this window, or nothing where both do. */
function unreadSources(measured: MeasuredRow): string | undefined {
  const unread = [...(measured.pullRequests ? [] : [EvidenceSource.PullRequests]), ...(measured.directCommits ? [] : [EvidenceSource.DirectCommits])];
  if (unread.length === 0) {
    return undefined;
  }
  return `cached ${unread.join(" and ")} evidence does not cover this window`;
}

/**
 * Whether a collection covered the whole of one window, with no gap left in it.
 *
 * THE INTERVALS AND NOT THE FRONT EDGE, which is where this parts company with `measuredSources`. An estate row
 * asks whether the last collection reached the repository at all, and one instant answers it; a series asks the
 * same question of fourteen windows reaching back further than any collection fills, so it has to know where the
 * gaps are. `findMissingIntervals` needs them sorted by `startsAt`, which is the order `getSourceCoverage` reads
 * them back in.
 */
function covers(window: ReportingWindow, intervals: readonly Interval[]): boolean {
  return findMissingIntervals(window, intervals).length === 0;
}

/**
 * The facts of one window, taken out of a read that spans the whole series.
 *
 * Half-open, `[startsAt, endsAt)`, like every window in the system: a merge at exactly `endsAt` belongs to the
 * next period and never to both.
 */
function within(walked: Merges, window: ReportingWindow): Merges {
  const from = window.startsAt.getTime();
  const to = window.endsAt.getTime();
  const inside = (at: Date): boolean => at.getTime() >= from && at.getTime() < to;
  return {
    pullRequests: walked.pullRequests.filter((fact) => inside(fact.mergedAt)),
    directCommits: walked.directCommits.filter((fact) => inside(fact.committedAt))
  };
}

/** What moved between the baseline and one period: its counts, then every metric both windows observed. */
function periodDeltas(baseline: TrendThroughput, baselineMetrics: readonly TrendMetric[], period: ResolvedWindow): contract.TrendDelta[] {
  const throughput = period.throughput;
  return [...(throughput === undefined ? [] : throughputDeltas(baseline, throughput)), ...metricDeltas(baselineMetrics, period.metrics)].map(contractDelta);
}

/**
 * One resolved window in the contract's own spelling.
 *
 * `provenance` says `offline` because a series is cut from what a collection left and never fetches an interval
 * to draw a page — the same claim `builtRepositoryEvidence` makes for the block above it.
 */
function contractWindow(resolved: ResolvedWindow): contract.TrendWindow {
  return {
    starts_at: resolved.window.startsAt.toISOString(),
    ends_at: resolved.window.endsAt.toISOString(),
    provenance: { offline: true, intervals_fetched: 0 },
    cohort: resolved.cohort,
    ...(resolved.throughput === undefined ? {} : { throughput: contractThroughput(resolved.throughput) }),
    metrics: resolved.metrics.map(contractMetric),
    ...(resolved.detail === undefined ? {} : { detail: resolved.detail })
  };
}

/**
 * One window's throughput as the contract spells it, plus the one figure the comparison does not name.
 *
 * `active_contributors` IS REPORTED AND NOT COMPARED, which is upstream's split rather than an omission:
 * `throughputMeasures` names the three measures a series moves on, and a change in the number of people is a
 * change in the team rather than in its practice. It is counted over both routes, so a person who only pushed
 * directly is still someone who put work on the default branch.
 */
function contractThroughput(throughput: TrendThroughput): contract.TrendThroughput {
  return {
    merges: throughput.merges,
    merged_pull_requests: throughput.mergedPullRequests,
    direct_commits: throughput.directCommits,
    active_contributors: throughput.activeContributors
  };
}

/**
 * One metric's observation renamed for the contract.
 *
 * THROUGH `contractObservation`, which is the one statement of that translation: the domain holds `sampleSize`
 * and `percentile75`, and `src/lib/types.ts` declares `sample_size` and `percentile_75`. Both files call the
 * interface `DistributionObservation`, so handing the domain object over type-checks and then prints "undefined
 * samples" — see `./contract/observation.ts` for where that shipped.
 */
function contractMetric(metric: TrendMetric): contract.TrendMetric {
  return {
    metric: metric.metric,
    summary: contractObservation(metric.summary),
    ...(metric.value === undefined ? {} : { value: metric.value }),
    ...(metric.percentile === undefined ? {} : { percentile: metric.percentile })
  };
}

/**
 * One delta in the contract's own spelling.
 *
 * REBUILT RATHER THAN PASSED THROUGH even though every field name happens to agree today, for the reason
 * `contractRate` is: a spread would leave this silently right now and silently wrong the day either side renames
 * a field, and the contract re-declares `TrendDelta` under the same name so nothing would object.
 */
function contractDelta(computed: TrendDelta): contract.TrendDelta {
  return {
    measure: computed.measure,
    basis: computed.basis,
    baseline: computed.baseline,
    period: computed.period,
    ...(computed.change === undefined ? {} : { change: computed.change }),
    ...(computed.unit === undefined ? {} : { unit: computed.unit }),
    ...(computed.percentile === undefined ? {} : { percentile: computed.percentile }),
    ...(computed.detail === undefined ? {} : { detail: computed.detail })
  };
}
