---
name: gitlab
description: GitLab issues via the glab CLI
requires: [glab]
config_key: integrations.gitlab
---

# Provider: GitLab

Reads work items from GitLab Issues using the `glab` CLI for auth +
transport (no PAT in config needed — `glab auth status` must be green).

## When to use

Enable this if your team tracks work in **GitLab Issues**. This is
the provider for anyone hosting code on GitLab.com or a self-managed
GitLab instance.

## Config schema

Add to `bridge-config.yaml`:

```yaml
integrations:
  gitlab:
    enabled: true

    # Repos (GitLab calls these "projects") to pull issues from,
    # as OWNER/REPO or GROUP/NAMESPACE/REPO
    repos:
      - my-group/my-project
      - my-group/other-project

    # Optional — used to flag assigned_to_me
    assignee_me: my-gitlab-username

    # Optional — max items per repo (default 50)
    limit: 50
```

All fields except `enabled` are optional. An enabled-but-empty config
still works (the provider will emit zero items and briefing skips the
section).

## Collect

When `/briefing` Stream B loads this file, Claude runs:

### 1. For each configured repo — fetch open issues

```bash
glab issue list --repo {repo} --assignee {assignee_me} \
  --output json --per-page {limit}
```

If `assignee_me` is not set, omit `--assignee` and fetch all open
issues for the repo instead.

### 2. For each issue — fetch full detail if needed

```bash
glab issue view {id} --repo {repo} --output json
```

Only needed if the list output is missing a field the schema requires
(labels and state are already present in list output for `glab`).

### 3. Normalize each item

Map each raw item to the shared schema in `trackers/README.md`:

| Normalized field | Source |
|---|---|
| `id` | `"#" + iid` |
| `title` | `title` |
| `raw_state` | `state` (`opened` / `closed`) |
| `state` | from state map below |
| `type` | from labels (see type rules) |
| `assignee` | `assignees[0].username` |
| `assigned_to_me` | `assignee_me` ∈ `assignees[*].username` |
| `url` | `web_url` |
| `changed_at` | `updated_at` |
| `project` | repo path |
| `tracker` | `"gitlab"` |
| `labels` | `labels[*]` |
| `priority` | label starting with `priority:` or `P1`/`P2` |
| `category` | see category rules below |

### 4. Emit the combined list

## State mapping

GitLab issues only have two raw states (`opened`, `closed`) — unlike
GitHub's labeled project columns, there's no native "in progress" or
"in review" state. Use labels to refine, falling back to the raw
state:

| raw_state / label | state |
|---|---|
| `closed` | `done` |
| label `in-progress`, `doing` | `in_progress` |
| label `in-review`, `review` | `review` |
| label `blocked` | `blocked` |
| `opened`, no matching label | `ready` |

A user can override this mapping by adding `state_map:` under
`integrations.gitlab` in bridge-config.yaml.

## Type mapping

Derive `type` from labels, first match wins:

| Label pattern | type |
|---|---|
| `bug`, `defect`, `incident` | `bug` |
| `feature`, `enhancement` | `feature` |
| `epic` | `epic` |
| `story`, `user-story` | `story` |
| `task`, `chore` | `task` |
| (none of the above) | `issue` |

## Category rules

| Rule | category |
|---|---|
| `state == done` | `done` |
| `state == review` AND `assigned_to_me == true` | `qa` |
| any label in `["needs-qa", "needs-testing", "qa-queue"]` | `qa` |
| otherwise | `open` |

## Failure modes

| Condition | Action |
|---|---|
| `glab` not installed (`command -v glab` fails) | Warning, skip provider |
| `glab auth status` not green | Warning with hint to run `glab auth login`, skip |
| Repo not accessible (404 / 403) | Warning for that repo only, continue with other repos |
| Single command >10s | Timeout, skip that command, continue |
| JSON parse error | Warning, skip that command's items |
| Zero items across everything | Briefing omits the GitLab section |

None of these abort `/briefing`.

## Example run

With a config like `repos: [my-group/my-project]` and
`assignee_me: alice`, a run produces normalized items in this shape:

```json
[
  {
    "id": "#42",
    "title": "Example issue title",
    "state": "ready",
    "raw_state": "opened",
    "type": "bug",
    "assignee": "alice",
    "assigned_to_me": true,
    "url": "https://gitlab.example.com/my-group/my-project/-/issues/42",
    "changed_at": "2026-01-15T12:00:00Z",
    "project": "my-group/my-project",
    "tracker": "gitlab",
    "labels": ["bug"],
    "priority": null,
    "category": "open"
  }
]
```

## Related

- `trackers/README.md` — the shared contract this file implements
