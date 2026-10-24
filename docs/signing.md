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

## Operator steps (once; the advisor, with the owner account)

Needs `cryptography` (the orch-core venv has it). Nothing here prints a private key; do not `cat` the key files.

```
cd ~/orch-dev/orch-marketplace          # a checkout that has scripts/gen-index-keys (develop after PR B)
D=$(mktemp -d ~/orch-dev/.tkeys-XXXX)   # mode 0700, short path; the only place the private keys exist
~/orch-dev/orch-core/plugins/orch-core/.venv/bin/python scripts/gen-index-keys --out "$D"
#   prints the OFFICIAL_KEYS block (public halves only, current first) and writes $D/current.key and $D/next.key (0600)

# 1. Environment limited to main, plus its non-secret variable (the pinned public halves, comma separated, current first)
gh api -X PUT repos/severinlindenmann/orch-marketplace/environments/index-signing \
  --input - <<< '{"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}'
gh api -X POST repos/severinlindenmann/orch-marketplace/environments/index-signing/deployment-branch-policies \
  -f name=main -f type=branch
gh variable set ORCH_MARKET_INDEX_PUBS --env index-signing --repo severinlindenmann/orch-marketplace --body "<current-pub>,<next-pub>"

# 2. The current private key becomes the Environment secret, straight from the file
gh secret set ORCH_MARKET_INDEX_KEY --env index-signing --repo severinlindenmann/orch-marketplace < "$D/current.key"

# 3. The next private key goes to Proton Pass (vault Agents; see the proton-pass skill). The key reaches the CLI by stdin
#    template, never as an argument:
source <(~/orch-dev/scripts/pass-login.sh)
python3 -c 'import json,sys; print(json.dumps({"title":"orch market index key (next)","password":open(sys.argv[1]).read(),"urls":[]}))' "$D/next.key" \
  | PROTON_PASS_AGENT_REASON="store next official index key (M#3)" pass-cli item create login --vault-name Agents --from-template -

# 4. Paste the printed public halves into the orch-core pin PR (m3-pin-keys, constants.py), mark it ready, merge it.

# 5. Delete the private-key files (only mktemp paths under ~/orch-dev/.t*-XXXX are accepted)
~/orch-dev/scripts/rmtmp.sh "$D"
```

Then, on the owner account: allow GitHub Actions to create pull requests (Settings > Actions > General), and run the
workflow once (Actions > sign-index > Run workflow, branch `main`). If the Environment has a required reviewer, approve
that first run. The workflow opens `chore(index): re-sign marketplace.json`; close and reopen the PR once so the
required `index` check runs, then merge it (the Actions token starts no checks). After that, core (with the pin merged)
accepts the official index.

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
* A refresh raises `version` by one. A host that has seen a version keeps its signed payload; the same version with a new
  `expires_at` would be `market.rollback` in core's `check_floor`.
* The owner merges. A signed index that nobody merges stays unpublished; core shows the old one as stale after
  `expires_at` and keeps working (spec 3.1). With a 10-day window and a daily check there are 20 days to merge.

## Adding an entry

Index PR (raise `version`, new entry pinned to a main commit; see the README) is merged first; the push to main starts the
workflow, which signs the entry (`publisher`) and the index in the next PR.

## Rotation

`next.key` is the second pinned key. To rotate: ship a core release that pins a fresh next key, switch the secret to the
next private key and `ORCH_MARKET_INDEX_PUBS` to the new pair. `sign-index` refuses to overwrite an entry `publisher`
made by a different key, so re-keying existing entries needs a `--rekey` option that does not exist yet (follow-up,
not needed before the first rotation).
