# 403 Forbidden Buster v8 — Release Validation Record

This file records the manual release validation performed for the v8 accuracy/safety release candidate. The detailed test plan remains in `V8_SMOKE_TEST.md`.

## Release candidate

| Field | Value |
| :--- | :--- |
| Branch | `feat/v8-accuracy-engine` |
| Tested source commit | `800b359234888c6019c538961fb25bd4289b5d10` |
| Tested JAR SHA-256 | `6444de5fdfc7cc0c0e336ff4305680b01a9a618cbfb0ab23f367900813de1ccb` |
| Provenance artifact | `ForbiddenBuster-v8-800b359234888c6019c538961fb25bd4289b5d10` |
| Artifact ZIP SHA-256 | `a48ac1bbd4f10ea893b07ce48f6d79f1a3acf7fde290577a1aaa2317bbd25fe9` |
| Burp | Community Edition `v2026.7.3` |
| Build/CI Java | Java 17 |
| Test date | `2026-08-29` |
| Tester | `tobiasGuta` |
| Test target | Disposable local Docker smoke-test lab |
| Manual verdict | **PASS** |

The exact tested code commit passed GitHub Actions CI run **#134** before manual validation. The validation-record commit that adds this file is documentation-only; it does not modify extension source or detector behavior.

## Manual validation summary

The release candidate was exercised in Burp against a disposable local lab with request logging so UI decisions could be correlated with actual transmitted traffic.

### Extension defaults and execution safety — PASS

- Extension loaded successfully and exposed the v8 UI.
- **Protocol Representation Variants (Experimental)** was visibly marked experimental, disabled by default, and documented as potentially normalized by Burp on send.
- Safe Mode and Active Methods banners/warnings behaved as designed.
- Active Methods permission did not persist across extension reload/target changes.
- A denied non-GET target in Active Methods skipped automatic baseline replay.
- Method Tampering selected under Safe Mode was rejected before transmission; the lab recorded `0` requests for that validation attempt.
- Safe Mode Header Injection transmitted safe GET/header variants while the lab recorded no POST/PUT/PATCH/DELETE/TRACE/CONNECT escape.

### Baselines, Pause/Stop, and global rate limiting — PASS

- Stable GET calibration used the captured baseline plus two live replays.
- A deliberately unstable baseline aborted before mutation traffic.
- Pause during calibration stopped traffic until Resume.
- A visible 2000 ms delay applied across baseline/control/candidate traffic.
- Stop was recognized as `Attack Stopped by user` and the final hard-stop network check recorded only the two baseline requests, with no control/candidate request escaping afterward.

### Path-swap controls and candidate scoring — PASS

- Generic/public carrier behavior for `X-Original-URL` / `X-Rewrite-URL` was suppressed rather than reported as a bypass.
- Target-specific routing to `/admin-route` remained visible as `BYPASS_CANDIDATE`.
- Stable candidates revalidated at `3/3` with confidence `100`.
- A `2/3` candidate was downgraded to `STATUS_ANOMALY` with confidence `55`.
- A `1/3` candidate was downgraded to `STATUS_ANOMALY` with confidence `40`.
- Fresh paired controls were observed during safe candidate revalidation.

### Host/routing paired controls — PASS

- A generic/default-vhost `200` was suppressed when the protected target matched its synthetic control.
- A target-specific Host-routing response remained a `BYPASS_CANDIDATE` at confidence `100`, repeatability `3/3`.
- `X-Forwarded-Host` generic/catch-all behavior was exercised with the same mutation on target and synthetic control and was suppressed.
- Traffic logs confirmed the routing mutation/session context was preserved while the planned synthetic control path differed.

### Redirect triage and normalization — PASS

- `/login` redirects remained low-confidence `REDIRECT` (`15`).
- Equivalent candidate/control redirects were suppressed.
- Meaningfully different redirect destinations remained visible as `REDIRECT`, not `BYPASS_CANDIDATE`.
- A `302` without usable `Location` remained low-confidence `REDIRECT` (`20`).
- Absolute redirect normalization treated scheme/host case, default port, and fragment-only differences as equivalent.
- Meaningful query differences remained visible.
- Evidence preserved `%2Fprotected`; it was not rewritten as `%252Fprotected`.

### Evidence UI, semantic evidence, and CSV — PASS

A final known-good `/admin-route` run produced two green rows:

- `X-Original-URL=/admin-route` — `BYPASS_CANDIDATE`, confidence `100`, status `200`, baseline similarity `0.0%`, control similarity `0.0%`, repeatability `3/3`.
- `X-Rewrite-URL=/admin-route` — same evidence profile.

The selected Candidate response rendered the expected protected `200` content. The Evidence tab showed classification, confidence, status, baseline/control similarity, redirect/semantic rationale where applicable, repeatability, and revalidation rationale.

The exported CSV parsed successfully as two records with these columns:

`ID, Confidence, Classification, Method, URL, Technique, Category, Status, Length, BaselineSimilarity, ControlCompared, ControlStatus, ControlSimilarity, Repeatability, Rationale, RevalidationRationale`

Both CSV rows matched the Burp table and contained `ControlCompared=true`, `ControlStatus=200`, `ControlSimilarity=0.0%`, `Repeatability=3/3`, and the revalidation rationale `Repeatability 3/3; candidate remained stable across all safe replays`.

Montoya semantic evidence remained supplemental: it appeared in rationale/evidence but did not independently promote redirects or unstable candidates into bypass candidates.

## Release-blocker review

No release-blocking behavior was observed during the manual validation:

- **No Safe Mode method escape** was observed.
- **No request escaped the verified Stop barrier**.
- **No generic public/default-vhost response was surfaced as a bypass when its paired control matched**.
- **No login/auth redirect received high-confidence bypass treatment**.
- **No unstable `2/3` or `1/3` candidate remained a high-signal bypass candidate**.
- **No candidate/evidence/CSV mismatch was observed in the final sanity check**.
- **No unhandled extension exception was observed on the normal smoke-test path**.

## Accepted non-blocking observations

These are intentionally deferred rather than changed in the release candidate:

1. With **Hide 404 Responses** disabled, large scans can show many low-confidence `404 STATUS_ANOMALY` rows. They are not bypass candidates, but they can add UI noise.
2. The configuration labels make ownership of some forwarded-host payloads less obvious: `X-Forwarded-Host` belongs to the IP Spoofing header family rather than the `Header Injection (Proto/Port/Host)` family. This is a minor naming/UX observation, not a detector correctness issue.
3. Several local smoke-lab revisions were required to isolate Host and redirect-control scenarios. Those corrections were to the lab conditions; they did not require changes to the tested extension JAR.

## Release decision

**Manual v8 release validation: PASS.**

The detector/source code is frozen at tested commit `800b359234888c6019c538961fb25bd4289b5d10`. No additional detector feature or cleanup change should be introduced as part of this validation record.

Next gate: require CI to remain green on this documentation-only validation commit, then PR #1 may be moved from Draft to Ready for Review. Merging/releasing remains a separate explicit decision.
