import { isHumanAccount } from "../behaviour/analysis.ts";
import { parseResponse } from "../behaviour/responses.ts";
import { AliasAnswer, readAliasedBatch, reaskable } from "../github/aliased-batch.ts";
import type { GitHubClient } from "../github/client.ts";
import { type CodeownersOwners, mergeCodeowners, parseCodeowners } from "./codeowners.ts";
import {
  byCodePoint,
  type CodeownersFact,
  CodeownersPaths,
  canonical,
  isOwningAccess,
  mostPermissiveAccess,
  type OrgFacts,
  type PersonFact,
  type RepositoryFact,
  type TeamFact,
  type TeamMembershipFact,
  type TeamRepositoryFact
} from "./graph.ts";
import {
  DefaultOwnershipBatchSize,
  orgPeopleQuery,
  orgRepositoriesQuery,
  orgTeamsQuery,
  ownershipFilesQuery,
  teamMembersQuery,
  teamRepositoriesQuery
} from "./queries.ts";
import {
  collaboratorsSchema,
  type MemberConnection,
  orgPeopleSchema,
  orgRepositoriesSchema,
  orgTeamsSchema,
  ownershipEntry,
  ownershipFilesSchema,
  type TeamNode,
  type TeamRepositoryConnection,
  teamAccess,
  teamMembersSchema,
  teamRepositoriesSchema
} from "./responses.ts";

/**
 * Collecting the organisation graph from GitHub. Ported from `scripts/build_team_configuration.py`.
 *
 * EVERY WALK HERE DEGRADES RATHER THAN ABORTS, which is the rule `behaviour/collect.ts` follows per repository
 * and which matters more at this scale: one team of 336 that a token may not read must not cost the other 335,
 * and a graph covering most of the estate is worth far more than an exit that covers none of it. A failure is
 * therefore LOGGED AND COUNTED — the client's own outcome counters record the status — and the walk goes on.
 *
 * The one distinction the callers must not lose is between "nobody claims this" and "nobody could look", which
 * is why `teamsRead` exists beside an empty team list and why a `CodeownersFact` carries a `refusal` instead of
 * empty owners. Reporting the second as the first states a fact nobody observed.
 */

/**
 * What the team walk answers, as the slice of `OrgFacts` it fills plus WHAT IT SAW IN FULL.
 *
 * The three completeness fields are not bookkeeping — they decide whether the writer may read an absence as a
 * departure. Each walk here degrades quietly and independently: a per-team refusal is caught and the run
 * continues, and the team list itself can stop paging while the teams already read stay perfectly good. Without
 * them, one refused membership closed every one of that team's live rows as though everybody had left, and
 * GitHub cannot be asked to confirm otherwise afterwards.
 */
export interface OrgTeamFacts extends Pick<OrgFacts, "teamsRead" | "knownTeams" | "teams" | "memberships" | "teamRepositories"> {
  /**
   * Whether the whole team list was paged without a refusal.
   *
   * Distinct from `teamsRead`, which only says the FIRST page answered. A walk that read 200 of 336 teams and
   * then hit a rate limit has `teamsRead: true` and `teamsComplete: false` — and the 136 it never reached must
   * not be recorded as teams that were deleted.
   */
  teamsComplete: boolean;
  /** Team slugs whose membership was read in full. Only these may have a departure inferred from an absence. */
  membershipsObserved: Set<string>;
  /** Team slugs whose repository list was read in full. */
  teamRepositoriesObserved: Set<string>;
}

/** What a flat organisation-wide walk answers, beside whether it reached the end. */
export interface OrgWalk<Fact> {
  facts: Fact[];
  /**
   * Whether the walk paged to the end.
   *
   * `false` means it returned the prefix it managed — which is worth storing, and must never be read as the
   * whole estate. A rate limit at page 5 of 33 would otherwise supersede some 1,500 live repository rows.
   */
  complete: boolean;
}

/** One failure's message, for a log line that names what went wrong rather than that something did. */
function reason(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** One team as the organisation listed it. */
function teamFact(node: TeamNode): TeamFact {
  return {
    slug: node.slug,
    // The slug stands in for a missing display name rather than an empty string, so a row always names
    // something a reader can look up.
    name: node.name ?? node.slug,
    ...(node.description == null || node.description === "" ? {} : { description: node.description }),
    ...(node.privacy == null ? {} : { privacy: node.privacy }),
    ...(node.parentTeam?.slug == null ? {} : { parentSlug: node.parentTeam.slug })
  };
}

/**
 * Folds one page of member edges into a team's memberships, keyed by folded login.
 *
 * KEYED WHILE COLLECTING for the reason `orgTeamsQuery` orders its nested connections: a connection served
 * across pages can repeat an edge, and a person counted twice in one team would inflate every team-size
 * comparison the ladder's tie-breaks are decided by.
 */
function readMembers(slug: string, connection: MemberConnection, into: Map<string, TeamMembershipFact>): void {
  for (const edge of connection.edges) {
    const login = edge?.node?.login;
    if (edge == null || login == null) {
      // An edge GitHub would not name a node for: a member whose account this token may not see. Nothing can
      // be recorded about a person with no login, and the team keeps every member that WAS named.
      continue;
    }
    // `MEMBER` when GitHub named no role: the weaker of the two, so an absent field can never invent a
    // maintainer. The word is GitHub's own, kept SCREAMING as `TeamMembershipFact` documents.
    into.set(canonical(login), { teamSlug: slug, login, role: edge.role ?? "MEMBER" });
  }
}

/**
 * Folds one page of repository edges into a team's access, keeping only ownership.
 *
 * `pull` and `triage` are dropped here rather than downstream, because read access says only that a team MAY
 * LOOK — which platform and security teams hold across the whole organisation, so counting it would bury every
 * specific claim under the same handful of org-wide handles. See `OwningAccessLevels`.
 *
 * `isArchived` is read and deliberately NOT filtered on: a team's access to an archived repository is still a
 * fact about that team, and the archived flag the report acts on comes from the repository walk, which is the
 * one place it is authoritative for every repository rather than only for held ones.
 */
function readTeamRepositories(slug: string, connection: TeamRepositoryConnection, into: Map<string, TeamRepositoryFact>): void {
  for (const edge of connection.edges) {
    const name = edge?.node?.name;
    if (edge == null || name == null) {
      continue;
    }
    const access = teamAccess(edge.permission);
    if (access === undefined) {
      // Debug rather than warning: a permission GitHub adds later is not a fault in this run, and it is not
      // demoted to `pull` either — see `teamAccess`.
      console.debug(`Ignoring an unrecognised permission '${edge.permission}' on ${slug} → ${name}`);
      continue;
    }
    if (!isOwningAccess(access)) {
      continue;
    }
    const key = canonical(name);
    const existing = into.get(key);
    into.set(key, {
      teamSlug: slug,
      // GitHub's first spelling of the name is kept, so a repository arriving twice under different case does
      // not change key between runs.
      repository: existing?.repository ?? name,
      access: mostPermissiveAccess(existing?.access, access)
    });
  }
}

/** Every member of one team, issuing continuations only after the bounded connection in the bulk walk overflows. */
async function collectTeamMembers(client: GitHubClient, organization: string, slug: string, connection: MemberConnection): Promise<TeamMembershipFact[]> {
  const memberships = new Map<string, TeamMembershipFact>();
  readMembers(slug, connection, memberships);
  let info = connection.pageInfo;
  while (info.hasNextPage) {
    const data: unknown = await client.graphql(teamMembersQuery(), { organization, slug, cursor: info.endCursor ?? null });
    const next = parseResponse(teamMembersSchema, data, "team member data").organization?.team?.members;
    if (next == null) {
      // GitHub answered without the team a page of it was just read from. Nothing more can be asked for, so
      // the team keeps the members already collected rather than the walk spinning on the same cursor.
      console.warn(`GitHub omitted ${organization}/${slug} while continuing its members; keeping the ${memberships.size} already read`);
      break;
    }
    readMembers(slug, next, memberships);
    info = next.pageInfo;
  }
  return [...memberships.values()];
}

/** Every repository one team holds, issuing continuations only after the bounded connection overflows. */
async function collectTeamRepositories(
  client: GitHubClient,
  organization: string,
  slug: string,
  connection: TeamRepositoryConnection
): Promise<TeamRepositoryFact[]> {
  const held = new Map<string, TeamRepositoryFact>();
  readTeamRepositories(slug, connection, held);
  let info = connection.pageInfo;
  while (info.hasNextPage) {
    const data: unknown = await client.graphql(teamRepositoriesQuery(), { organization, slug, cursor: info.endCursor ?? null });
    const next = parseResponse(teamRepositoriesSchema, data, "team repository data").organization?.team?.repositories;
    if (next == null) {
      console.warn(`GitHub omitted ${organization}/${slug} while continuing its repositories; keeping the ${held.size} already read`);
      break;
    }
    readTeamRepositories(slug, next, held);
    info = next.pageInfo;
  }
  return [...held.values()];
}

/**
 * Every team of the organisation, who is in it, and what it holds.
 *
 * A REFUSAL TO LIST TEAMS AT ALL IS REPORTED AND RETURNS `teamsRead: false` WITH EMPTY SETS — it is not thrown.
 * A token without `read:org` is the ordinary case for a GitHub App installation, and CODEOWNERS files and
 * repository names can still attribute most of an organisation without a single team row: a graph that covers
 * every repository on weaker evidence is worth more than an exit that covers none.
 *
 * A REFUSAL ON ONE TEAM'S MEMBERS OR REPOSITORIES IS REPORTED AND THAT TEAM CLAIMS NOTHING, BUT IT STAYS IN
 * `knownTeams`. A team whose repositories nobody was allowed to list is a team that EXISTS, and `knownTeams` is
 * the authority a handle read out of a CODEOWNERS file is checked against — dropping it would turn every
 * mention of that team in a CODEOWNERS file into an unrecognised handle.
 *
 * A failure PART WAY THROUGH the walk keeps `teamsRead: true` and the teams already read. The flag answers "was
 * this token allowed to list teams", which the first successful page settles; a truncated list is reported with
 * the count it reached so a reader can see it is short.
 */
export async function collectOrgTeams(client: GitHubClient, organization: string): Promise<OrgTeamFacts> {
  const facts: OrgTeamFacts = {
    teamsRead: false,
    // Complete until something proves otherwise: an organisation with no teams at all is completely read.
    teamsComplete: true,
    knownTeams: new Set<string>(),
    teams: [],
    memberships: [],
    teamRepositories: [],
    membershipsObserved: new Set<string>(),
    teamRepositoriesObserved: new Set<string>()
  };
  let cursor: string | null = null;

  for (;;) {
    let connection: ReturnType<typeof parseTeams>;
    try {
      const data: unknown = await client.graphql(orgTeamsQuery(), { organization, cursor });
      connection = parseTeams(data);
    } catch (error) {
      console.warn(
        facts.teamsRead
          ? `Could not list further teams of ${organization} after ${facts.teams.length}; keeping the teams already read: ${reason(error)}`
          : `Could not list the teams of ${organization}; the graph will be built without team access: ${reason(error)}`
      );
      facts.teamsComplete = false;
      break;
    }
    if (connection == null) {
      // GitHub answered with no organisation, or with an organisation carrying no teams connection: for this
      // purpose the same answer as a refusal — nobody listed the teams.
      console.warn(`GitHub named no teams connection for ${organization}; the graph will be built without team access`);
      facts.teamsComplete = false;
      break;
    }

    facts.teamsRead = true;
    for (const node of connection.nodes) {
      if (node == null) {
        continue;
      }
      facts.teams.push(teamFact(node));
      facts.knownTeams.add(canonical(node.slug));
      try {
        facts.memberships.push(...(await collectTeamMembers(client, organization, node.slug, node.members)));
        facts.membershipsObserved.add(canonical(node.slug));
      } catch (error) {
        console.warn(`Could not list the members of ${organization}/${node.slug}; it will claim no people: ${reason(error)}`);
      }
      try {
        facts.teamRepositories.push(...(await collectTeamRepositories(client, organization, node.slug, node.repositories)));
        facts.teamRepositoriesObserved.add(canonical(node.slug));
      } catch (error) {
        console.warn(`Could not list the repositories of ${organization}/${node.slug}; it will claim no repositories: ${reason(error)}`);
      }
    }

    if (!connection.pageInfo.hasNextPage) {
      break;
    }
    cursor = connection.pageInfo.endCursor ?? null;
  }

  return facts;
}

/** Named so the loop above can annotate the connection without restating the schema's inferred shape. */
function parseTeams(data: unknown) {
  return parseResponse(orgTeamsSchema, data, "organisation team data").organization?.teams;
}

/**
 * Every repository the organisation owns.
 *
 * A failure returns the repositories already read rather than throwing, on the same rule as the team walk —
 * but note the asymmetry with `teamsRead`: there is no flag for a short repository list, because a repository
 * nobody listed is simply absent from the report, whereas a team nobody listed silently rewrites what every
 * remaining rung concludes.
 */
export async function collectOrgRepositories(client: GitHubClient, organization: string): Promise<OrgWalk<RepositoryFact>> {
  const repositories: RepositoryFact[] = [];
  let complete = true;
  let cursor: string | null = null;

  for (;;) {
    let connection: ReturnType<typeof parseRepositories>;
    try {
      const data: unknown = await client.graphql(orgRepositoriesQuery(), { organization, cursor });
      connection = parseRepositories(data);
    } catch (error) {
      console.warn(`Could not list the repositories of ${organization} after ${repositories.length}: ${reason(error)}`);
      complete = false;
      break;
    }
    if (connection == null) {
      console.warn(`GitHub named no repositories connection for ${organization}`);
      complete = false;
      break;
    }

    for (const node of connection.nodes) {
      if (node == null) {
        continue;
      }
      repositories.push({
        name: node.name,
        // Absent flags read as the safer answer: not archived, not a fork, visibility unstated. Each is a
        // filter downstream, and a missing field must not exclude a repository that exists.
        archived: node.isArchived ?? false,
        isFork: node.isFork ?? false,
        visibility: node.visibility ?? "",
        ...(node.defaultBranchRef?.name == null ? {} : { defaultBranch: node.defaultBranchRef.name }),
        ...(node.pushedAt == null ? {} : { pushedAt: node.pushedAt }),
        // ABSENT STAYS ABSENT rather than falling back to `pushedAt`. GitHub omits the default branch ref for an
        // empty repository, and reporting the any-branch push date under a field that promises the default branch
        // is the confusion this field exists to end — see `RepositoryFact.defaultBranchCommittedAt`.
        ...(node.defaultBranchRef?.target?.committedDate == null ? {} : { defaultBranchCommittedAt: node.defaultBranchRef.target.committedDate })
      });
    }

    if (!connection.pageInfo.hasNextPage) {
      break;
    }
    cursor = connection.pageInfo.endCursor ?? null;
  }

  return { facts: repositories, complete };
}

function parseRepositories(data: unknown) {
  return parseResponse(orgRepositoriesSchema, data, "organisation repository data").organization?.repositories;
}

/**
 * Every member of the organisation and the role they hold.
 *
 * The three self-reported fields are omitted when blank rather than stored as empty strings, so a row carrying
 * a name means somebody typed one — `PersonFact` treats all three as decoration, and an empty string would be
 * decoration that looks like data.
 */
export async function collectOrgPeople(client: GitHubClient, organization: string): Promise<OrgWalk<PersonFact>> {
  const people = new Map<string, PersonFact>();
  let complete = true;
  let cursor: string | null = null;

  for (;;) {
    let connection: ReturnType<typeof parsePeople>;
    try {
      const data: unknown = await client.graphql(orgPeopleQuery(), { organization, cursor });
      connection = parsePeople(data);
    } catch (error) {
      console.warn(`Could not list the members of ${organization} after ${people.size}: ${reason(error)}`);
      complete = false;
      break;
    }
    if (connection == null) {
      console.warn(`GitHub named no membership connection for ${organization}`);
      complete = false;
      break;
    }

    for (const edge of connection.edges) {
      const node = edge?.node;
      if (edge == null || node == null) {
        continue;
      }
      people.set(canonical(node.login), {
        login: node.login,
        // `MEMBER` when GitHub named no role, for the reason a membership defaults to it: never invent an owner.
        role: edge.role ?? "MEMBER",
        ...(blank(node.name) ? {} : { name: node.name as string }),
        ...(blank(node.email) ? {} : { email: node.email as string }),
        ...(blank(node.company) ? {} : { company: node.company as string })
      });
    }

    if (!connection.pageInfo.hasNextPage) {
      break;
    }
    cursor = connection.pageInfo.endCursor ?? null;
  }

  return { facts: [...people.values()], complete };
}

function parsePeople(data: unknown) {
  return parseResponse(orgPeopleSchema, data, "organisation membership data").organization?.membersWithRole;
}

function blank(value: string | null | undefined): boolean {
  return value == null || value.trim() === "";
}

/** A repository whose CODEOWNERS could not be read, as a fact rather than as an absence. */
function refused(repository: string, refusal: string): CodeownersFact {
  return { repository, teams: [], people: [], paths: [], refusal };
}

/**
 * Every repository's CODEOWNERS owners, batched through one document per `batchSize` repositories.
 *
 * THREE OUTCOMES, and they are all different: no entry in the returned map means no CODEOWNERS file was found
 * at any of GitHub's three paths; an entry with a `refusal` means nobody could read one; an entry with paths
 * and empty owners means a file was read and names nobody. Collapsing the middle into either of the others is
 * the mistake `CodeownersFact` was shaped to prevent.
 */
export async function collectCodeowners(
  client: GitHubClient,
  organization: string,
  repositories: string[],
  batchSize: number = DefaultOwnershipBatchSize
): Promise<Map<string, CodeownersFact>> {
  const facts = new Map<string, CodeownersFact>();
  const size = Math.max(1, Math.trunc(batchSize));
  for (let at = 0; at < repositories.length; at += size) {
    await readOwnershipBatch(client, organization, repositories.slice(at, at + size), facts);
  }
  return facts;
}

/**
 * Reads one batch, CONSUMING THE ALIASES GITHUB ANSWERED and asking again only for the ones it did not.
 *
 * A batch is 25 repositories in one document, and GitHub answers a query naming one repository nobody may see
 * with HTTP 200, the aliases it could resolve, a `null` for the one it could not and an error saying why. This
 * used to treat the whole response as a failure and re-read all 25 — so one archived-and-transferred name cost
 * the twenty-four beside it a call each. The 24 are read from the response now, and the re-ask names only the
 * repository that went unanswered.
 *
 * The re-ask still runs at most once per batch: `reaskable` returns nothing for a batch whose every alias went
 * unanswered, so a batch of one never splits further.
 */
async function readOwnershipBatch(client: GitHubClient, organization: string, batch: string[], facts: Map<string, CodeownersFact>): Promise<void> {
  if (batch.length === 0) {
    return;
  }
  const variables: Record<string, unknown> = { organization };
  for (const [index, name] of batch.entries()) {
    variables[`r${index}`] = name;
  }

  let body: Record<string, unknown>;
  let byAlias: ReadonlyMap<string, string>;
  try {
    // Typed as a record rather than `unknown`, so `data === undefined` narrows to the branch that carries a
    // failure: `unknown` includes `undefined`, which would make the union undiscriminatable.
    const answer = await client.graphqlPartial<Record<string, unknown>>(ownershipFilesQuery(batch.length), variables);
    if (answer.data === undefined) {
      // Errors and NO data: GitHub answered about nothing. Split exactly as it always was —
      // `MAX_NODE_LIMIT_EXCEEDED` takes this shape and is answerable one repository at a time, and this is not
      // the case the cost bug was about.
      await reReadOneAtATime(client, organization, batch, facts, answer.failure.summary);
      return;
    }
    body = parseResponse(ownershipFilesSchema, answer.data, "CODEOWNERS data");
    byAlias = answer.failure?.byAlias ?? new Map();
  } catch (error) {
    // NOTHING ARRIVED, so nothing is consumed and the batch is split, unchanged. A document too complex for
    // GitHub to serve can succeed one repository at a time.
    await reReadOneAtATime(client, organization, batch, facts, reason(error));
    return;
  }

  // Positional: `f<n>` is the answer for `$r<n>`, which `readOwnershipRepository` then proves against the name
  // GitHub echoed back.
  const entries = readAliasedBatch("f", batch, body, byAlias);
  for (const entry of entries) {
    if (entry.answer === AliasAnswer.Answered) {
      readOwnershipRepository(organization, entry.repository, entry.value, facts);
      continue;
    }
    // REFUSED, NOT ABSENT, and now with GitHub's own reason attached. An absence in this map means no
    // CODEOWNERS file was found, so a repository GitHub would not answer for must never fall into it.
    facts.set(entry.repository, refused(entry.repository, entry.refusal as string));
  }

  for (const name of reaskable(entries)) {
    await readOwnershipBatch(client, organization, [name], facts);
  }
}

/**
 * Re-reads a batch NOTHING was answered for, one repository at a time.
 *
 * The behaviour a whole-batch failure has always had, kept for the failures that are still whole-batch ones. A
 * batch of one takes the second branch and records the refusal rather than splitting further, so this runs at
 * most one extra pass over a failing batch.
 */
async function reReadOneAtATime(
  client: GitHubClient,
  organization: string,
  batch: readonly string[],
  facts: Map<string, CodeownersFact>,
  detail: string
): Promise<void> {
  if (batch.length > 1) {
    console.warn(`Could not read CODEOWNERS for a batch of ${batch.length} repositories, re-reading them one at a time: ${detail}`);
    for (const name of batch) {
      await readOwnershipBatch(client, organization, [name], facts);
    }
    return;
  }
  const only = batch[0] as string;
  console.warn(`Could not read CODEOWNERS for ${organization}/${only}: ${detail}`);
  facts.set(only, refused(only, detail));
}

/**
 * Reads one repository's blobs into a fact, at every path GitHub resolves CODEOWNERS from.
 *
 * A TRUNCATED BLOB REFUSES THE REPOSITORY RATHER THAN BEING PARSED, and the owners already read from its other
 * paths are dropped with it. Half a CODEOWNERS file parses perfectly and resolves to the owners named in its
 * first half, so a truncated read does not fail — it answers, confidently and wrongly, and a subset naming one
 * team would fire the `codeowners-sole` rung for a repository whose file names four.
 *
 * ONLY EVER GIVEN A NODE GITHUB NAMED. An alias that came back `null`, and one the response did not carry at
 * all, are both recorded as refusals by the caller in GitHub's own words — they are answers about the response
 * rather than about the repository's file.
 */
function readOwnershipRepository(organization: string, repository: string, value: unknown, facts: Map<string, CodeownersFact>): void {
  let entry: ReturnType<typeof ownershipEntry>;
  try {
    entry = ownershipEntry(value);
  } catch (error) {
    facts.set(repository, refused(repository, reason(error)));
    return;
  }

  // The one check that guards the aliasing scheme: `f3` must be the repository `$r3` named, or the batch has
  // been read off by one and every owner in it belongs to the wrong repository.
  if (entry.name !== undefined && canonical(entry.name) !== canonical(repository)) {
    console.warn(`GitHub answered for ${organization}/${entry.name} where ${repository} was asked for; refusing the answer`);
    facts.set(repository, refused(repository, `GitHub answered for ${entry.name}`));
    return;
  }

  const paths: string[] = [];
  const files: CodeownersOwners[] = [];
  for (const [at, path] of CodeownersPaths.entries()) {
    const blob = entry.files[at];
    if (blob?.text == null) {
      continue;
    }
    if (blob.isTruncated === true) {
      const size = blob.byteSize === null || blob.byteSize === undefined ? "an unreported size" : `${blob.byteSize} bytes`;
      console.warn(`${organization}/${repository} ${path} was truncated at ${size}; refusing to read half a CODEOWNERS file`);
      facts.set(repository, refused(repository, `${path} was truncated at ${size}`));
      return;
    }
    paths.push(path);
    files.push(parseCodeowners(blob.text, organization));
  }

  if (paths.length === 0) {
    // Absent, which is the commonest answer in this estate and is NOT recorded as a fact: the map's own
    // silence is what "there is no CODEOWNERS file" looks like, kept distinct from a stored refusal.
    return;
  }
  facts.set(repository, { repository, paths, ...mergeCodeowners(files) });
}

/**
 * The people holding admin on a repository DIRECTLY, rather than through a team.
 *
 * `affiliation: direct` is what makes this worth asking: without it GitHub returns every collaborator a team
 * grants, which is the evidence the team rungs already read, one REST call per repository. This is the last
 * rung before falling back to names, so it is asked ONLY for the repositories CODEOWNERS left open — the caller
 * chooses the list, and it is measured in dozens rather than thousands.
 *
 * Bots are excluded through `isHumanAccount`, one definition of "is this a bot" shared with the behaviour
 * metrics: `dependabot[bot]` holds admin on a fair number of repositories and is not an owner of any of them.
 *
 * A repository whose collaborators nobody may list gets NO ENTRY, so an unread repository stays distinguishable
 * from one whose only admins are teams and bots — which is recorded as an entry with an empty list.
 */
export async function collectDirectAdmins(client: GitHubClient, organization: string, repositories: string[]): Promise<Map<string, string[]>> {
  const admins = new Map<string, string[]>();

  for (const repository of repositories) {
    const logins = new Set<string>();
    try {
      for await (const page of client.paginate<unknown>(`/repos/${organization}/${repository}/collaborators`, {
        affiliation: "direct",
        permission: "admin",
        per_page: 100
      })) {
        for (const collaborator of parseResponse(collaboratorsSchema, page, "direct collaborator data")) {
          if (collaborator == null) {
            continue;
          }
          if (!isHumanAccount(collaborator.login, collaborator.type ?? undefined)) {
            continue;
          }
          // Folded, because the other source of individual owners — a bare handle in CODEOWNERS — is folded
          // too, and one person must not be two owners because two APIs disagreed about case.
          logins.add(canonical(collaborator.login));
        }
      }
    } catch (error) {
      console.warn(`Could not list the direct collaborators of ${organization}/${repository}: ${reason(error)}`);
      continue;
    }
    admins.set(repository, [...logins].sort(byCodePoint));
  }

  return admins;
}
