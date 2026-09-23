import { AvailabilityReason, GitHubError } from "../domain/availability.ts";
import { type SonarDeclaration, SonarResolutionMethod, type StoredSonarMapping } from "../domain/sonar.ts";
import type { GitHubClient } from "../github/client.ts";
import { type SonarClient, SonarError, searchableRevisions } from "./client.ts";

/**
 * Attributing a SonarCloud project to a GitHub repository. Ported from `metrics.sonar`'s resolution half.
 *
 * THE REPOSITORY DIRECTION, and the cheap one. `collect` asks this of every repository in the estate and pays
 * nothing for the answer: `./attribute.ts` has already spent the commit-search quota building the map, so this
 * is a lookup in it plus, where a repository declares a key the map has never seen, one core-quota commit read.
 * `cli/index.ts`'s `sonarSource` is the caller, and `report/contract/sonar.ts` puts what it establishes in front
 * of a reader.
 *
 * THE LADDER, in the order it is climbed:
 *   1. `configured`                     — an explicit `sonar_projects:` override in the policy file settles it.
 *   2. `declared_confirmed_by_map`      — the repository declares a key, and the stored map agrees.
 *   3. `declared_confirmed_by_commit`   — the declared project's latest analysed commit is one of ours.
 *   4. `stored_map`                     — no declaration, but the map already attributes a project.
 *
 * RUNGS 2 AND 3 ARE UNREACHABLE FROM `collect` TODAY, and that is a cost decision rather than an oversight: a
 * declaration is read from a repository's own `sonar-project.properties`, which this port fetches for nothing
 * else, so reaching them means one content call per repository across the estate to obtain a hypothesis the map
 * answers anyway. They are exercised by the suite and stand ready for a collection that does read the file.
 *
 * NAME MATCHING IS ABSENT ON PURPOSE. It was measured and rejected: wrong for 6 of 70 projects, which is close
 * enough to look right and wrong often enough to mislead.
 */

const SONAR_PROPERTIES_PATH = "sonar-project.properties";
const PROJECT_KEY_PROPERTY = "sonar.projectKey";

/** GitHub and SonarCloud names are case-insensitive, so every comparison folds. */
export function namesRepository(left: string | undefined, right: string | undefined): boolean {
  return (left ?? "").toLowerCase() === (right ?? "").toLowerCase();
}

/** The outcome of testing one declaration: a mapping, or a note saying why not, or a reason to record. */
export interface DeclarationCheck {
  mapping?: StoredSonarMapping;
  note?: string;
  reason?: AvailabilityReason;
}

/**
 * The project key one repository declares, or the note saying why its declaration cannot be used.
 *
 * A key declared for ANOTHER SonarCloud organisation is discarded here rather than tested: the project it
 * names is not in the organisation this run reads, so confirming it would attribute one organisation's quality
 * gate to another's repository.
 */
export function declaredKey(declaration: SonarDeclaration | undefined, sonarOrganization: string): { key?: string; note?: string } {
  if (declaration === undefined) {
    return {};
  }
  if (declaration.projectKey === undefined) {
    return { note: `${SONAR_PROPERTIES_PATH} declares no ${PROJECT_KEY_PROPERTY}` };
  }
  if (declaration.organization !== undefined && !namesRepository(declaration.organization, sonarOrganization)) {
    return {
      note: `${SONAR_PROPERTIES_PATH} declares ${declaration.projectKey} in the ${declaration.organization} organisation, not ${sonarOrganization}`
    };
  }
  return { key: declaration.projectKey };
}

/**
 * Whether one repository holds the commit a declared project was last analysed against.
 *
 * The cheap confirmation: one core-quota commit read, not the 30-a-minute search. A 404 or 422 means the
 * repository does not hold it, which is a refutation rather than a failure.
 */
export async function confirmsCandidate(client: GitHubClient, organization: string, repository: string, revision: string): Promise<boolean> {
  try {
    await client.get(`/repos/${organization}/${repository}/commits/${revision}`);
    return true;
  } catch (error) {
    if (error instanceof GitHubError && (error.status === 404 || error.status === 422)) {
      return false;
    }
    throw error;
  }
}

/**
 * Asks whether the repository holds the commit the declared project was last analysed against.
 *
 * A DECLARED KEY SONARCLOUD DOES NOT LIST IS REFUTED, NOT A FAILED CALL. SonarCloud answers 404 for a project
 * that does not exist, and 123 of one organisation's 240 declarations named one — they are stale keys left in
 * properties files. Carrying that out as a failure reason would record one repository's stale properties file
 * as a collection failure and fail the run for half the organisation. Only a read that was REFUSED —
 * unauthenticated, forbidden, rate limited, or unparseable — keeps its reason.
 *
 * A project with no analysed commit cannot be confirmed this way and is left UNCONFIRMED rather than refuted:
 * nothing was learned about it, which is not the same as learning it is wrong.
 */
export async function confirmByCommit(
  sonarClient: SonarClient,
  githubClient: GitHubClient,
  organization: string,
  repository: string,
  key: string,
  now: Date
): Promise<DeclarationCheck> {
  let revisions: { revision: string; analysisAt?: Date }[];
  try {
    revisions = searchableRevisions(await sonarClient.projectAnalyses(key, 1));
  } catch (error) {
    if (!(error instanceof SonarError)) {
      throw error;
    }
    const refuted = error.reason === AvailabilityReason.NotFoundOrInaccessible;
    return refuted ? { note: `SonarCloud lists no project ${key}` } : { note: error.message, reason: error.reason };
  }

  const latest = revisions[0];
  if (latest === undefined) {
    return { note: `the declared project ${key} has no analysed commit to confirm it by` };
  }

  let confirmed: boolean;
  try {
    confirmed = await confirmsCandidate(githubClient, organization, repository, latest.revision);
  } catch (error) {
    if (error instanceof GitHubError) {
      return { note: error.message, reason: error.reason };
    }
    throw error;
  }

  if (!confirmed) {
    return { note: `${repository} does not hold commit ${latest.revision}, the latest analysis of ${key}` };
  }
  return {
    mapping: {
      projectKey: key,
      repository,
      method: SonarResolutionMethod.DeclaredConfirmedByCommit,
      ...(latest.analysisAt === undefined ? {} : { analysisAt: latest.analysisAt }),
      revision: latest.revision,
      resolvedAt: now
    }
  };
}

/**
 * Tests whether the repository that declares one project key is the repository that project analyses.
 *
 * THE MAP ANSWERS FIRST AND FOR NOTHING, and it REFUTES as readily as it confirms: a declared key the map
 * attributes to another repository is the shared-template case, where 14 repositories declare one template's
 * key and at most one of them owns it. Only where the map has never resolved the declared project is a call
 * spent.
 */
export async function checkDeclaration(
  sonarClient: SonarClient,
  githubClient: GitHubClient,
  organization: string,
  repository: string,
  key: string,
  stored: StoredSonarMapping | undefined,
  now: Date
): Promise<DeclarationCheck> {
  if (stored?.repository !== undefined) {
    if (!namesRepository(stored.repository, repository)) {
      return { note: `the declared project ${key} is mapped to ${stored.repository}` };
    }
    return {
      mapping: {
        projectKey: key,
        repository: stored.repository,
        method: SonarResolutionMethod.DeclaredConfirmedByMap,
        ...(stored.analysisAt === undefined ? {} : { analysisAt: stored.analysisAt }),
        ...(stored.revision === undefined ? {} : { revision: stored.revision }),
        resolvedAt: now
      }
    };
  }
  return confirmByCommit(sonarClient, githubClient, organization, repository, key, now);
}

/**
 * Restates the map's answer as this direction's resolution, keeping the evidence behind it.
 *
 * The method is rewritten to `stored_map` because that is how THIS resolution was arrived at, while
 * `analysisAt` and `revision` are the map's own — the commit that attributed the project to the repository in
 * the first place, which is the evidence a doubted mapping is re-checked from.
 */
export function mappedProject(claimed: StoredSonarMapping, candidates: number, repository: string, now: Date): StoredSonarMapping {
  if (candidates > 1) {
    console.info(`${repository} is claimed by ${candidates} SonarCloud projects; reading the most recently analysed, ${claimed.projectKey}`);
  }
  return {
    projectKey: claimed.projectKey,
    ...(claimed.repository === undefined ? {} : { repository: claimed.repository }),
    method: SonarResolutionMethod.StoredMap,
    ...(claimed.analysisAt === undefined ? {} : { analysisAt: claimed.analysisAt }),
    ...(claimed.revision === undefined ? {} : { revision: claimed.revision }),
    resolvedAt: now
  };
}

/**
 * Resolves which SonarCloud project analyses one repository, climbing the ladder.
 *
 * `configuredKey` short-circuits everything: it is a decision somebody made, and the schema already refuses a
 * blank one so it cannot silently mean "unresolved".
 */
export async function resolveRepositoryProject(options: {
  sonarClient: SonarClient;
  githubClient: GitHubClient;
  organization: string;
  sonarOrganization: string;
  repository: string;
  configuredKey?: string;
  declaration?: SonarDeclaration;
  storedByProject: (key: string) => StoredSonarMapping | undefined;
  storedByRepository: (repository: string) => { mapping: StoredSonarMapping; candidates: number } | undefined;
  now: Date;
}): Promise<DeclarationCheck> {
  const { sonarClient, githubClient, organization, sonarOrganization, repository, configuredKey, declaration, storedByProject, storedByRepository, now } =
    options;

  if (configuredKey !== undefined && configuredKey.trim() !== "") {
    return { mapping: { projectKey: configuredKey, repository, method: SonarResolutionMethod.Configured, resolvedAt: now } };
  }

  const { key, note } = declaredKey(declaration, sonarOrganization);
  if (key !== undefined) {
    const checked = await checkDeclaration(sonarClient, githubClient, organization, repository, key, storedByProject(key), now);
    if (checked.mapping !== undefined || checked.reason !== undefined) {
      return checked;
    }
    // The declaration was refuted, so fall through to the map: a repository declaring a shared template's key
    // may still have a project of its own that the map knows about.
    const claimed = storedByRepository(repository);
    return claimed === undefined ? checked : { mapping: mappedProject(claimed.mapping, claimed.candidates, repository, now) };
  }

  const claimed = storedByRepository(repository);
  if (claimed !== undefined) {
    return { mapping: mappedProject(claimed.mapping, claimed.candidates, repository, now) };
  }
  return note === undefined ? {} : { note };
}
