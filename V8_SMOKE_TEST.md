# 403 Forbidden Buster v8 — Manual Burp Smoke Test

This checklist is the release gate for v8. It is intentionally focused on trust: false-positive resistance, traffic safety, evidence quality, and Burp runtime behavior. A green CI build is required, but CI alone is not enough to mark the release ready.

## Release candidate record

Fill this in before testing:

| Field | Value |
| :--- | :--- |
| Branch | `feat/v8-accuracy-engine` |
| Commit SHA | |
| JAR SHA-256 | |
| Burp edition/version | |
| Java version | |
| Test date | |
| Tester | |

Build the exact candidate under test with:

```bash
cd ForbiddenBuster
./gradlew clean test jar
```

Load only `ForbiddenBuster/build/libs/ForbiddenBuster.jar` produced from the recorded commit.

## Test rules

- Use only a local lab, CTF, staging system, or another target you are explicitly authorized to test.
- Prefer a disposable target for Active Methods testing.
- Keep **Protocol Representation Variants (Experimental)** disabled for the main release smoke test.
- Do not treat a green row or high confidence as proof of a vulnerability. Verify the protected resource/action manually.
- Record unexpected network traffic, UI behavior, exceptions, and misclassifications even if the scan technically completes.

## A. Extension load and defaults

| ID | Test | Expected result | Pass/Fail | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| A1 | Load the JAR into Burp | Extension loads without exceptions and identifies itself as v8 | | |
| A2 | Open Configuration | Safe defaults are visible; Protocol Representation Variants are marked **Experimental** | | |
| A3 | Fresh settings/profile | Experimental protocol variants are disabled by default | | |
| A4 | Hover experimental protocol option | Tooltip states that Burp may normalize the actual network protocol | | |
| A5 | Select a 401/403 GET with Safe Mode context menu | Target banner visibly says `SAFE MODE` | | |
| A6 | Select a target with Active Methods context menu and cancel warning | Active mode is not enabled | | |
| A7 | Confirm Active Methods for an authorized disposable target | Target banner visibly says `ACTIVE METHODS` | | |
| A8 | Reload extension | Active Methods permission does not persist across reload | | |

## B. Baseline calibration

| ID | Test | Expected result | Pass/Fail | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| B1 | Stable GET target returning 401/403 | Captured baseline + two live replays are accepted before fuzzing | | |
| B2 | Make one live baseline replay return a different status | Scan aborts as unstable/stale; no mutation traffic follows | | |
| B3 | Non-GET target in Active Methods | Automatic baseline replay is skipped | | |
| B4 | Press Stop during baseline rate-limit wait | No additional request is sent after Stop | | |
| B5 | Pause during calibration | Traffic stops until Resume | | |

## C. Path-swap paired controls

Use an authorized endpoint such as `/admin` that is denied in the baseline.

| ID | Test | Expected result | Pass/Fail | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| C1 | Server ignores `X-Original-URL`; `/` is public | Candidate matches neutral `/` control and is suppressed as `CONTROL_MATCH` | | |
| C2 | Same behavior with `X-Rewrite-URL` | Suppressed as `CONTROL_MATCH` | | |
| C3 | Routing header produces target-specific protected content while neutral `/` remains public | Candidate differs from control and may become `BYPASS_CANDIDATE`; exact content still requires manual validation | | |
| C4 | Dictionary swap points at a different resource such as `/login` | Payload is skipped by semantic-target guard rather than scored | | |
| C5 | Captured request already has the routing header | Control restores the original header value rather than deleting legitimate context | | |

## D. Host/routing paired controls

| ID | Test | Expected result | Pass/Fail | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| D1 | Mutated `Host` reaches a generic/default virtual host | Protected target and synthetic control match; result is `CONTROL_MATCH` | | |
| D2 | `X-Forwarded-Host` produces a generic catch-all page | Suppressed as `CONTROL_MATCH` | | |
| D3 | Selected routing mutation returns target-specific response while synthetic non-target path differs | Differential remains visible for candidate scoring/manual validation | | |
| D4 | Inspect Candidate and Control tabs | Both use the same routing mutation/session context; only the planned control path differs | | |
| D5 | Repeat the same routing candidate | Deterministic synthetic control path is reused | | |

## E. Candidate repeatability

| ID | Test | Expected result | Pass/Fail | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| E1 | Initial safe GET candidate remains stable on both replays | `3/3`; retains `BYPASS_CANDIDATE` | | |
| E2 | One replay collapses back to denied/control behavior | `2/3`; downgraded to `STATUS_ANOMALY`, confidence no higher than 55 | | |
| E3 | Both replays fail consistency | `1/3`; downgraded to `STATUS_ANOMALY`, confidence no higher than 40 | | |
| E4 | Stop interrupts revalidation | No further replay is sent | | |
| E5 | Paired-control candidate revalidation | A fresh control is sent before each candidate replay | | |
| E6 | Active/non-safe method produces candidate | Automatic revalidation is skipped and Evidence says manual validation is required | | |

## F. Redirect triage

| ID | Test | Expected result | Pass/Fail | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| F1 | Candidate redirects to `/login` or equivalent auth path | Remains low-confidence `REDIRECT` (<=15) | | |
| F2 | Candidate/control return same 3xx and equivalent non-empty `Location` | `CONTROL_MATCH`, confidence 0, suppressed | | |
| F3 | Candidate/control redirect to different destinations | Remains `REDIRECT`; evidence states destinations differ | | |
| F4 | Redirect has no usable `Location` | Remains low-confidence `REDIRECT` (<=20) | | |
| F5 | Equivalent absolute locations differ only by host case/default port/fragment | Normalized as equivalent | | |
| F6 | Redirect query values differ meaningfully | Not normalized away; difference remains visible | | |
| F7 | Encoded query contains `%2F` | Evidence preserves `%2F`; it is not rewritten as `%252F` | | |

## G. Safe Mode traffic boundary

| ID | Test | Expected result | Pass/Fail | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| G1 | Safe Mode on GET target with Method Tampering checkbox selected | Non-allowlisted method payloads do not transmit | | |
| G2 | Safe Mode Header Injection | Header-only GET/HEAD/OPTIONS variants may run | | |
| G3 | Safe Mode Header Injection POST Content-Type variants | Filtered before queue/send | | |
| G4 | Safe Mode on a POST/PUT/PATCH/DELETE target | Scan validation refuses automatic transmission | | |
| G5 | Active Methods confirmation accepted on disposable authorized target | Active method families become eligible | | |
| G6 | Switch to a new target through normal Safe Mode action | Previous Active Methods permission does not carry over | | |

## H. Pause, Stop, and rate limiting

| ID | Test | Expected result | Pass/Fail | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| H1 | Pause while worker queue is populated | New sends stop; queued workers do not leak traffic | | |
| H2 | Resume | Scan continues without duplicate burst | | |
| H3 | Stop during global delay | Interrupted worker does not send afterward | | |
| H4 | Stop between control and candidate | Candidate is not sent after Stop | | |
| H5 | Configure visible non-zero delay | Baseline, controls, candidates, and revalidation all share the global limiter | | |

## I. Evidence UI and export

| ID | Test | Expected result | Pass/Fail | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| I1 | Select a normal candidate/anomaly row | Candidate request/response renders correctly | | |
| I2 | Select a paired-control row | Control request/response renders correctly | | |
| I3 | Open Evidence tab | Shows classification, confidence, baseline similarity, control similarity when applicable, repeatability, analyzer rationale, and revalidation rationale | | |
| I4 | Inspect row colors | Green is reserved for `BYPASS_CANDIDATE`; redirects orange; errors red; anomalies yellow; control/method behavior muted | | |
| I5 | Sort table by Confidence | Ordering remains stable and selected row still shows matching evidence | | |
| I6 | Export Evidence CSV | CSV includes classification, confidence, similarities, repeatability, rationale, and revalidation rationale | | |
| I7 | Open CSV with commas/quotes/newlines in rationale | Fields remain validly escaped | | |

## J. Montoya semantic evidence

| ID | Test | Expected result | Pass/Fail | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| J1 | Baseline contains ordinary dynamic variation | Stable semantic baseline ignores attributes/keyword counts that already vary normally | | |
| J2 | Candidate changes a baseline-stable semantic attribute | Evidence rationale records the semantic variation | | |
| J3 | Candidate changes denial-keyword counts | Evidence records the keyword-count variation | | |
| J4 | Paired candidate/control differ semantically | Candidate/control semantic variation appears in Evidence | | |
| J5 | Semantic analyzer encounters an internal/runtime problem | Scan continues; analyzer failure does not promote or abort the result | | |
| J6 | Compare traffic count with/without semantic evidence | No extra HTTP requests are introduced by semantic analysis | | |

## K. Experimental protocol representation check

This section is optional for v8 release acceptance because the feature is disabled by default.

| ID | Test | Expected result | Pass/Fail | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| K1 | Enable experimental protocol representation variants | Technique/category visibly says `Experimental` | | |
| K2 | Inspect generated evidence | Description says Burp may normalize the representation on send | | |
| K3 | Compare Burp's recorded/requested protocol with actual observed network behavior when possible | Do **not** claim a real HTTP/0.9 or HTTP/1.0 downgrade unless independently verified | | |

## L. Release gate

Do not mark PR #1 ready for review until all required sections A–J pass or every failure is explicitly understood and accepted.

Release blockers include:

- Any Safe Mode request escaping the GET/HEAD/OPTIONS boundary.
- Stop allowing an additional request after the stop barrier.
- A generic public carrier/default-vhost response appearing as `BYPASS_CANDIDATE` when its paired control matches.
- A login/auth redirect receiving high-confidence bypass treatment.
- Candidate/control evidence showing different authentication/session context caused by the extension.
- A `BYPASS_CANDIDATE` remaining high-signal after failed safe repeatability.
- Candidate rows/evidence mismatching the underlying request/response.
- Unhandled extension exceptions during the normal smoke-test path.

Final sign-off:

| Gate | Result |
| :--- | :--- |
| Automated CI green on exact RC commit | |
| Required manual smoke tests pass | |
| No unresolved release-blocking false positive | |
| No unresolved Safe Mode traffic escape | |
| Evidence UI/CSV manually inspected | |
| Experimental protocol wording verified | |
| Ready to mark Draft PR ready for review | |
