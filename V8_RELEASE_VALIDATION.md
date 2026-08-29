# 403 Forbidden Buster v8 — Release Validation Record

This file records the manual release validation performed for the v8 accuracy/safety release candidate. The detailed test plan remains in `V8_SMOKE_TEST.md`.

## Release candidate

| Field | Value |
| :--- | :--- |
| Branch | `feat/v8-accuracy-engine` |
| Originally tested source commit | `800b359234888c6019c538961fb25bd4289b5d10` |
| Originally tested JAR SHA-256 | `6444de5fdfc7cc0c0e336ff4305680b01a9a618cbfb0ab23f367900813de1ccb` |
| Original provenance artifact | `ForbiddenBuster-v8-800b359234888c6019c538961fb25bd4289b5d10` |
| Original artifact ZIP SHA-256 | `a48ac1bbd4f10ea893b07ce48f6d79f1a3acf7fde290577a1aaa2317bbd25fe9` |
| Post-review runtime-tested head | `dfdf91ea0b92658b979bd1504df9f0c779abae0a` |
| Post-review runtime-tested JAR SHA-256 | `a2dd99e7910d598a1f42e536de14dee2563ff1f20535906188eb55f87deb62be` |
| Post-review artifact | `ForbiddenBuster-v8-dfdf91ea0b92658b979bd1504df9f0c779abae0a` |
| Post-review artifact ZIP SHA-256 | `ac583a045cbd3caae06e1611890b2274ef55eaf34edd398f063b31cda68e1262` |
| Burp | Community Edition `v2026.7.3` |
| Build/CI Java | Java 17 |
| Test date | `2026-08-29` |
| Tester | `tobiasGuta` |
| Test target | Disposable local Docker smoke-test lab |
| Final manual verdict | **PASS** |

The exact originally tested code commit passed GitHub Actions CI run **#134** before manual validation. The post-review isolation-fix artifact tested manually also passed GitHub Actions CI run **#146** before the targeted retest.

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

## Release-blocker review from original RC

No release-blocking behavior was observed during the original manual validation:

- **No Safe Mode method escape** was observed in the tested static-mode scenarios.
- **No request escaped the verified Stop barrier**.
- **No generic public/default-vhost response was surfaced as a bypass when its paired control matched**.
- **No login/auth redirect received high-confidence bypass treatment**.
- **No unstable `2/3` or `1/3` candidate remained a high-signal bypass candidate**.
- **No candidate/evidence/CSV mismatch was observed in the final sanity check**.
- **No unhandled extension exception was observed on the normal smoke-test path**.

## Post-review Safe Mode isolation fix — PASS

A final code review after the original manual PASS identified a per-run isolation issue: `PairedControlPlanner` consulted the mutable global `ActiveMethodsRegistry` while an attack was executing. In a narrow race, selecting **Active Methods** for another target while an existing Safe Mode run was still calibrating could have changed the final method gate seen by that already-running scan.

The fix binds planner safety decisions to the immutable `AttackConfig` mode captured when the run starts:

- `PairedControlPlanner.plan(...)` requires the captured `activeMethodsEnabled` value.
- `AttackEngine` passes `config.isActiveMethodsEnabled()` during payload filtering and again inside the worker before transmission.
- The planner no longer consults `ActiveMethodsRegistry` during execution.
- Regression tests verify that a Safe Mode run remains Safe if the global registry later changes to Active Methods, and that an Active run keeps its captured mode if the registry later changes back.

Code-fix head: `068b727bc2fecf5c7c0494339f0be683e0ff04b7`. GitHub Actions CI run **#144** passed.

The exact post-review artifact used for the targeted manual retest was built from `dfdf91ea0b92658b979bd1504df9f0c779abae0a`; GitHub Actions CI run **#146** passed before the retest.

### Targeted mode-switch isolation retest

Configuration:

- Target A: `GET /admin-active-methods` selected in **Safe Mode**.
- Header Injection only.
- Request delay: `2000 ms`.
- Threads: `1`.
- While Target A was still running, Target B `GET /admin-route` was selected through **Active Methods...** and the warning was accepted. Target B was not launched as another attack.

Output ordering confirmed the intended race window was exercised:

```text
[403 Buster] Calibrating baseline with 2 live replay(s)...
[403 Buster] Baseline calibrated: 3 stable sample(s).
[403 Buster] Skipped 4 payload(s) at semantic-target or Safe Mode gates.
[403 Buster] Starting attack with 16 payloads | 1 threads | 2000ms delay | 3 baseline sample(s) | Montoya semantic profile=3 sample(s)
[403 Buster] Target set: localhost/admin-route — ACTIVE METHODS
[403 Buster] ACTIVE METHODS enabled for this target only: GET /admin-route
[403 Buster] Attack finished.
```

The lab request log recorded `23` requests total. Every recorded request used method `GET`. The log contained the expected Safe Mode Header Injection/header-routing traffic for `/admin-active-methods`, plus one manual `GET /admin-route` request used to select Target B. It contained **zero POST, PUT, PATCH, DELETE, TRACE, or CONNECT requests**.

This proves that changing the global UI mode to Active Methods during an already-running Safe Mode scan does not change that run's captured safety boundary.

**Targeted Safe Mode isolation retest: PASS.**

## Accepted non-blocking observations

These remain intentionally deferred:

1. With **Hide 404 Responses** disabled, large scans can show many low-confidence `404 STATUS_ANOMALY` rows. They are not bypass candidates, but they can add UI noise.
2. The configuration labels make ownership of some forwarded-host payloads less obvious: `X-Forwarded-Host` belongs to the IP Spoofing header family rather than the `Header Injection (Proto/Port/Host)` family. This is a minor naming/UX observation, not a detector correctness issue.
3. Several local smoke-lab revisions were required to isolate Host and redirect-control scenarios. Those corrections were to the lab conditions; they did not require detector changes.

## Release decision

**Final v8 manual release validation: PASS.**

All identified release-blocking safety checks are now cleared, including the post-review Safe Mode per-run isolation issue. The full original manual suite passed, the narrow post-review fix passed automated regression coverage, and the exact post-review artifact passed the targeted runtime retest.

The commits that record the final result are documentation-only. After CI is green on the final documentation head, PR #1 is ready for the explicit merge/release decision.
