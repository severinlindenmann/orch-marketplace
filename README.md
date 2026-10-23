# orch-marketplace

The **official add-on marketplace** for [orch](https://github.com/severinlindenmann/orch-core): a plain git repository
whose root holds a `marketplace.json` (format `orch.market/1`). There is no hosted registry. The spec is
[`orch-v2-marketplace.md`](https://github.com/severinlindenmann/orch-core/blob/develop/docs/architecture/orch-v2-marketplace.md)
in orch-core; the schema is copied here as `schema/market.v1.json`.

## The three shelves

| Shelf | What is on it | Where it comes from |
|---|---|---|
| Built in | Tech-agnostic add-ons: dashboard, start agent, terminals, worktrees, wiki, widgets, schedules, explorer, usage, estimate, model routing, quick tasks, activity, publish | shipped in orch core |
| **Official marketplace (this repo)** | Tool-specific add-ons maintained by orch: GitHub, Landing, later Jira, Slack, ... | this index |
| Other marketplaces | Any git repo with a `marketplace.json`, or a single add-on repo | refused until per-add-on OS-user isolation exists (#287) |

The index is empty for now. GitHub and Landing move in with G6 (#924).

## Installs are human-only

The index only says where a package is and which bytes to expect. It never runs anything and orch never trusts it
for what it names. Installing is done by a person in their own terminal or with their own device key
(`orch addon install`); agents and mandates cannot install or grant. What runs is decided by the owner's signed
`addon.granted` over the digest of the bytes orch fetched itself.

## Pins

Every entry in `addons` is pinned twice, with no branch, tag or range anywhere:

- `commit`: a full 40 or 64 hex git object id of the add-on repo;
- `package_sha256`: the package digest (ticket-format 8.1) of the directory `source.subdir` at that commit.

orch refuses an install if the fetched commit or the recomputed digest differs. The index `version` is raised at
every change; a lower version than one already seen is a rollback and is refused. The official index will also carry
`expires_at` and a signature by the official key pinned in core (spec 3.1); both are added by the release step, not
by hand.

## CI

`.github/workflows/ci.yml` runs `scripts/validate_index.py --fetch` on every pull request and push:

1. strict JSON, schema `schema/market.v1.json`, unique ids, sorted capabilities, canonical lower-case URLs, git host
   rule, rollback against the base branch's index;
2. for every entry: fetch the pinned commit (isolated git environment, no checkout, plumbing only), judge the tree
   by the package rules, recompute `package_sha256` and compare, check the manifest agrees with the entry.

Run it locally: `pip install -r requirements-ci.txt && python -m pytest -q tests && python scripts/validate_index.py --fetch`.

## Changing the index

Open a pull request into `develop`. Raise `version`. `main` takes changes from `develop` only through a pull
request approved by the owner (CODEOWNERS).

## License

[PolyForm Noncommercial 1.0.0](LICENSE).
