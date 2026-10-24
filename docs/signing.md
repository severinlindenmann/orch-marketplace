# Signing the official index (M#3)

Core verifies the official index against the public keys pinned in `orch/market/constants.py` (`OFFICIAL_KEYS`: the
current and the next key). The private keys never enter this repository, a log or a file outside the steps below.

| Piece | Where |
|---|---|
| `scripts/gen-index-keys` | makes the two P-256 keys; prints only the public halves; run once by the operator |
| `scripts/sign-index` | signs `marketplace.json` (index and every entry) and sets `expires_at`; reads the key from `ORCH_MARKET_INDEX_KEY` or stdin |
| `.github/workflows/sign-index.yml` | main only, Environment `index-signing`: signs, verifies, opens a PR |
| `scripts/market_sign.py` | message formats and sign/verify, equal to core (`tests/test_market_sign.py` checks it) |

Formats: public key = the 65-byte uncompressed point, signature = 64-byte `r||s`, both unpadded base64url; private key
file = the 32-byte scalar as one 43-character line and nothing else (no label, no newline).

## Who holds the keys (custody) - owner decision pending

The next key is pinned in core. Whoever holds either private key can sign an index every host accepts. Therefore **no
agent keeps the next key**, and it never goes into the agents' Proton Pass vault ("Agents"): every agent session on the dev
machine can read that vault without the owner. Two ways; the first is the default until the owner chooses.

| | A (default) | B (alternative) |
|---|---|---|
| Who runs `gen-index-keys` | the advisor, in a fresh `mktemp -d ~/orch-dev/.tkeys-XXXX` | the owner, on his own terminal |
| `current.key` | piped by the advisor into the Environment secret, never read or printed | the owner pipes it into the secret |
| `next.key` | **the owner** copies it into owner-only storage (his own vault or the encrypted offline backup); no agent reads or stores it | the owner stores it the same way |
| Agents receive | the two public halves | the two public halves |
| Both key files | deleted right after (the advisor runs `rmtmp.sh` once the owner confirmed the copy) | deleted by the owner |

The current key has no backup by design: if it is lost, switch to the next key (rotation, below). The agents never need a private key
again; the signing job has the current one in the Environment and nothing else does.

## Operator steps (once)

Needs `cryptography` (the orch-core venv has it). Nothing here prints a private key; nobody `cat`s the key files.

```
cd ~/orch-dev/orch-marketplace          # a checkout that has scripts/gen-index-keys (develop after PR B)
D=$(mktemp -d ~/orch-dev/.tkeys-XXXX)   # mode 0700, short path; the only place the private keys exist
PY=~/orch-dev/orch-core/plugins/orch-core/.venv/bin/python
$PY scripts/gen-index-keys --out "$D"
#   prints the OFFICIAL_KEYS block (public halves only, current first) and writes $D/current.key and $D/next.key (0600)

# 1. The Environment limited to main, and the public halves as a REPOSITORY variable (public keys, comma separated, current
#    first). It is a repository variable, not an Environment one, because the gate (ci.yml) reads it for re-sign PRs.
gh api -X PUT repos/severinlindenmann/orch-marketplace/environments/index-signing \
  --input - <<< '{"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}'
gh api -X POST repos/severinlindenmann/orch-marketplace/environments/index-signing/deployment-branch-policies \
  -f name=main -f type=branch
gh variable set ORCH_MARKET_INDEX_PUBS --repo severinlindenmann/orch-marketplace --body "<current-pub>,<next-pub>"

# 2. The current private key becomes the Environment secret, straight from the file
gh secret set ORCH_MARKET_INDEX_KEY --env index-signing --repo severinlindenmann/orch-marketplace < "$D/current.key"

# 3. THE OWNER (not an agent) copies $D/next.key into owner-only storage: his own vault or the encrypted offline backup.
#    Never the agents' Proton Pass vault, never a file in a repo, never a message.

# 4. Verify every stored copy BEFORE deleting anything. The secret exists (its value cannot be read back):
gh secret list --env index-signing --repo severinlindenmann/orch-marketplace      # shows ORCH_MARKET_INDEX_KEY
#    The owner checks that the stored next key is the pinned one (prints a public half; compare it with the second pinned key):
$PY scripts/gen-index-keys --public-of < "$D/next.key"     # the file the owner stored
#    ...and once more from the stored copy itself (pipe it from the vault: ... | $PY scripts/gen-index-keys --public-of).
#    A failed copy would otherwise lose the only one.

# 5. Paste the printed public halves into the orch-core pin PR (m3-pin-keys, constants.py), mark it ready, merge it.

# 6. Delete the private-key files (only mktemp paths under ~/orch-dev/.t*-XXXX are accepted)
~/orch-dev/scripts/rmtmp.sh "$D"
```

Then, on the owner account: allow GitHub Actions to create pull requests (Settings > Actions > General) and run the workflow
once (Actions > sign-index > Run workflow, branch `main`). If the Environment has a required reviewer, approve that first run.
**Keep code-owner review required** (ruleset `require_code_owner_review`, `* @severinlindenmann` in CODEOWNERS): the
same setting also lets the Actions token *approve* pull requests, and an Actions approval must never be enough to merge.
The workflow opens `chore(index): re-sign marketplace.json`; close and reopen the PR once so the required `index` check runs
(the Actions token starts no checks), then merge it. After that, core (with the pin merged) accepts the official index.

## What the workflow does

* Trigger: a change of `marketplace.json` on main, a daily check, manual. Always on main, always in `index-signing`.
* It refuses when the run is not main's tip or the workflow definition is not main's tip.
* `sign-index --if-needed --expect-pub <pinned keys>`: a secret whose public half is not pinned signs nothing. Signs when
  the signature is missing or invalid, an entry is unsigned, or fewer than 10 days remain; otherwise it changes nothing.
  `expires_at` = now + 30 days.
* It then verifies the file with the pinned public keys and `validate_index.py --official --fetch`, and opens a PR from a
  new branch `index-resign-<run>`. **The result is never pushed to main.** Reason: the key can then only ever produce a file
  the owner has looked at, main keeps its protection with no bypass actor, and the diff is small and checkable (only
  `expires_at`, `version`, entry `publisher`, `signature` differ; `sign-index` asserts this, the job refuses any other file).
* **Every file `sign-index` writes has the input version + 1** (first signing, after a develop -> main content change, a key
  switch, a plain refresh). A host that has seen a version keeps its signed payload; the same version with a different payload
  is `market.rollback` in core's `check_floor`, and the gate's rollback check against main's index refuses it too.
* The gate (`ci.yml`) treats `index-resign-<n>` heads specially: `marketplace.json` only, exactly one github-actions commit,
  and `sign-index --verify-only --pub $ORCH_MARKET_INDEX_PUBS` must pass. Commits added by anyone else fail the check.
* The owner merges. A signed index that nobody merges stays unpublished; core shows the old one as stale after
  `expires_at` and keeps working (spec 3.1). With a 10-day window and a daily check there are 20 days to merge.

## Adding an entry

Index PR (raise `version`, new entry pinned to a main commit; see the README) is merged first; the push to main starts the
workflow, which signs the entry (`publisher`) and the index in the next PR.

## After every re-sign: merge main back into develop

Each merged re-sign PR raises main's `version` and adds `expires_at`, entry `publisher` and `signature`. Develop does not have
them, so the next develop -> main promotion would fail "version lower" or conflict. After merging a re-sign PR:

```
gh pr create --repo severinlindenmann/orch-marketplace --base develop --head main \
  --title "chore: merge main (re-sign) back into develop" --body "Brings the signed index back; no other change."
```

(the re-sign PR's description carries this command). Merge it before any index PR on develop is promoted.

## Rotation

`next.key` is the second pinned key. Rotation (entries re-keyed, hosts accepting a known-key change) is not built:
`sign-index` refuses to overwrite an entry `publisher` made by a different key, and core's install TOFU would raise
`market.publisher_key_changed`. It is tracked as a core issue; do not rotate before it is done.
