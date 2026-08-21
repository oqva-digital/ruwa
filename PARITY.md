# PARITY.md — upstream parity checkpoint

ruwa is a from-scratch port: we have few contributors, so protocol fixes and
new WhatsApp server behaviors (enforcement, stanzas, version bumps) usually
land upstream first. This file records the **last commit of each upstream we
have swept** for parity-relevant changes, so the next sweep knows exactly
where to start. Update the checkpoint table + append to the log after every
sweep.

## Checkpoint

Last sweep: **2026-08-20**

| Upstream | Branch | Commit | Commit date | Why we track it |
|---|---|---|---|---|
| [tulir/whatsmeow](https://github.com/tulir/whatsmeow) | `main` | `fb386f152837` | 2026-08-16 | Primary porting reference: protocol logic, stanzas, auth/pairing, LID, app-state, media. Also the source of our advertised WA Web version. |
| [EvolutionAPI/evolution-api](https://github.com/EvolutionAPI/evolution-api) | `develop` | `e273b904d53f` | 2026-07-14 | Feature/API-surface parity + field reports of WA enforcement changes (large user base ⇒ issues surface fast). Active dev is on `develop`; `main` and the `evolution-foundation` org mirror are stale. |
| [WhiskeySockets/Baileys](https://github.com/WhiskeySockets/Baileys) | default | `0af238629290` | 2026-08-04 | Second protocol implementation to cross-check: platform/user-agent tweaks, pairing changes, ban-avoidance findings. |
| [oxidezap/whatsapp-rust](https://github.com/oxidezap/whatsapp-rust) | default | `fdf2214b716c` | 2026-08-19 | **Calls**: pure-Rust 1:1 VoIP stack (`src/voip/` — signaling, SRTP/DTLS transport, audio) merged in their PR #1024. Primary porting reference for ruwa call support (MIT). |
| [purpshell/meowcaller](https://github.com/purpshell/meowcaller) | default | `27a3c6b18657` | 2026-08-11 | **Calls**: pure-Go WA VoIP for whatsmeow — relay/STUN/RTP/SRTP, jitter/playout, and the proprietary MLOW codec reimplemented (MIT). Codec + media-plane reference; spec at wacrg.org. Pairs with whatsmeow PR #1201 (signaling, still open). |

Version pins at checkpoint:

- ruwa compiled-in WA Web version: `2.3000.1041871181` (`session.rs::WA_VERSION`,
  overridable at runtime via `RUWA_WA_VERSION`).
- whatsmeow advertised WA Web version at checkpoint: `2.3000.1045305987`
  (`store/clientpayload.go::waVersion`). **We are behind** — bump when convenient.

Issues swept through 2026-08-20 (whatsmeow + Baileys). Notable conclusions
already absorbed:

- `401 <conflict type="device_removed"/>` seconds after pairing = Meta
  server-side enforcement on restricted accounts (reachout timelock), not a
  client bug — whatsmeow #1055, #1173. ruwa's park-`Blocked` behavior is correct.
- No new mass block/ban mechanism reported through Aug 2026; recent upstream
  churn is calls, newsletters, LID edge cases.

## How to sweep (next time)

```sh
# 1. Commits since checkpoint (repeat per repo, swapping the SHA from the table):
gh api "repos/tulir/whatsmeow/compare/fb386f152837...HEAD" \
  -q '.commits[] | .sha[0:12] + "  " + (.commit.message | split("\n")[0])'
gh api "repos/EvolutionAPI/evolution-api/compare/e273b904d53f...develop" \
  -q '.commits[] | .sha[0:12] + "  " + (.commit.message | split("\n")[0])'
gh api "repos/WhiskeySockets/Baileys/compare/0af238629290...HEAD" \
  -q '.commits[] | .sha[0:12] + "  " + (.commit.message | split("\n")[0])'

# 2. Issues opened since the last sweep date:
gh api 'search/issues?q=repo:tulir/whatsmeow+created:>2026-08-20&sort=created&order=desc&per_page=30' \
  -q '.items[] | [.number, .created_at, .state, .title] | @tsv'
# (repeat for EvolutionAPI/evolution-api and WhiskeySockets/Baileys)

# 3. WA Web version drift:
gh api repos/tulir/whatsmeow/contents/store/clientpayload.go -q .content \
  | base64 -d | grep 'waVersion ='
```

Then: port anything relevant (see triage list below), bump the table SHAs +
sweep date, and append a log entry.

## What counts as parity-relevant

Prioritize upstream changes touching:

1. **Auth / pairing / login** — handshake, ClientPayload, pair-device, 515/401/403
   handling, phone pairing code.
2. **Advertised WA Web version** — whatsmeow bumps `waVersion`; stale versions
   eventually get `<failure reason="405">` (client outdated).
3. **LID / addressing** — LID migrations, `addressing_mode`, phash, device lists.
   (History: our worst outbound bugs were all here — PRs #49/#50/#51.)
4. **New stanzas / enforcement** — new `<notification>` types, stream errors,
   ban/timelock behaviors reported in issues.
5. **App-state / sync** — mutation protocols, key handling.
6. **Media** — upload/download routes, HMAC/key derivation changes.
7. **Ignore**: upstream CI, docs, bridge-specific (mautrix) code, Evolution's
   integrations (Chatwoot/Typebot/etc.) unless we ship the equivalent feature.

## Sweep log

- **2026-08-20 (b)** — call work started (F1: `call_offer`/`call_terminate`
  events + reject endpoint). Added the two call-stack references
  (whatsapp-rust voip, meowcaller) as tracked upstreams.
- **2026-08-20** — initial checkpoint. Trigger: investigating
  `device_removed`-after-pairing on new numbers (concluded: Meta reachout
  timelock, no ruwa change needed). Swept whatsmeow/Baileys issues to date;
  noted WA version drift (ruwa `…1041871181` vs whatsmeow `…1045305987`).
