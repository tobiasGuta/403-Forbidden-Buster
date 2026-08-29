# 403 Forbidden Buster (Burp Suite Extension)

**An Automated 403 Bypass Fuzzer for Burp Suite Community & Professional**

![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white) ![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=for-the-badge&logo=burpsuite&logoColor=white) ![Security](https://img.shields.io/badge/Cybersecurity-Bug_Bounty-red?style=for-the-badge)

## Overview
**403 Forbidden Buster** is a Burp Suite extension designed to automate testing of `403 Forbidden` and `401 Unauthorized` endpoints.

When a security professional encounters a restricted page (for example `/admin` or `/api/private`), manually testing every bypass technique is time-consuming. This extension allows the user to right-click the captured Burp request and launch a background scan using common bypass heuristics while preserving the original request context.

Version 8 is accuracy-, safety-, and evidence-focused. A status change alone is not treated as proof of an authorization bypass. Results are compared with calibrated denied baselines, neutral paired controls where appropriate, Burp-native semantic response evidence, and safe repeatability checks for high-signal GET candidates. Safe Mode is the default execution profile; non-GET/HEAD/OPTIONS request families require a per-target Active Methods opt-in.

---

## Key Features
* **150+ Bypass Techniques:** Automated fuzzing with header poisoning, path obfuscation, method tampering, Unicode normalization, backslash tricks, routing variants, and more. Experimental protocol-representation variants are clearly labeled and disabled by default.
* **Safe Mode by Default:** Automatic transmission is limited to GET/HEAD/OPTIONS technique families. Non-allowlisted methods are gated behind an explicit per-target confirmation and are never persisted as the default.
* **Safe Header Injection Coverage:** Forwarding, Host, Accept, and related header-only mutations remain available in Safe Mode, while POST Content-Type variants are filtered before queueing unless Active Methods is explicitly enabled.
* **Calibrated Baselines:** Safe GET targets are replayed before fuzzing to learn normal response variance and reject stale authorization baselines.
* **Paired Differential Controls:** Target-preserving path swaps and selected Host/routing mutations are evaluated against neutral controls so public carrier pages, catch-all routes, and default virtual hosts are not mistaken for protected-resource access.
* **Semantic-Target Guard:** Dictionary path swaps that point at a different resource are skipped instead of being scored as target bypasses.
* **Burp-Native Semantic Evidence:** Montoya response-variation and keyword analyzers track semantic attributes and denial-keyword count changes that move outside the calibrated baseline profile. This evidence supplements, but never independently promotes, the custom bypass classifier.
* **Location-Aware Redirect Triage:** Redirect destinations are normalized and compared explicitly. Identical candidate/control redirects are suppressible as `CONTROL_MATCH`, while login/authentication/denial redirects remain low-confidence manual-inspection signals.
* **Safe Candidate Revalidation:** High-signal GET candidates are replayed twice. Only a stable `3/3` result retains `BYPASS_CANDIDATE`; paired-control techniques receive a fresh neutral control on every replay.
* **Evidence-Based Classification:** Status, method semantics, normalized body similarity, denial markers, body length, paired-control differences, repeatability, and supplemental Burp-native semantic evidence are surfaced for triage.
* **Evidence-First Burp UI:** Classification, confidence, baseline/control similarity, repeatability, exact candidate/control traffic, and rationale are visible without treating every `2xx` as a bypass.
* **Attack Controls:** Pause, resume, and stop attacks on demand. Queued workers respect pause, and Stop acts as a send barrier.
* **Evidence-Rich CSV Export:** Export classification, confidence, similarities, repeatability, and rationales for reporting and further analysis.
* **Global Rate Limiting:** Enforced across baseline calibration, paired controls, candidate revalidation, and attack requests.
* **Persistent Configuration:** Ordinary scan settings are saved across Burp restarts. Active Methods permission is intentionally not persisted.
* **Release Trust Gate:** v8 includes a manual Burp smoke-test checklist (`V8_SMOKE_TEST.md`) that must pass before the release is considered ready.

---

## Architecture

The extension follows a modular architecture with clean separation of concerns:

| File | Responsibility |
| :--- | :--- |
| `ForbiddenBuster.java` | Entry point — registers extension, tab, Safe/Active context-menu actions, unload handler |
| `BusterUI.java` | Evidence-first Swing UI, persistence, candidate/control viewers, CSV export, result table |
| `AttackEngine.java` | Baseline calibration, paired-control execution, Montoya semantic evidence, safe candidate revalidation, traffic controls, global rate limiting |
| `AttackConfig.java` | Immutable configuration plus effective Safe Mode technique gates |
| `ActiveMethodsRegistry.java` | Stores the current target's ephemeral Safe/Active execution choice; never persisted |
| `RequestSafetyPolicy.java` | Central GET/HEAD/OPTIONS method allowlist and execution-mode decision |
| `BypassResult.java` | Stores candidate evidence, classification, confidence, paired-control evidence, and repeatability metadata |
| `PayloadGenerator.java` | Generates bypass payloads from the effective technique configuration |
| `PairedControlPlanner.java` | Final pre-queue Safe Mode gate plus semantic-target, path-swap, and Host/routing control planning |
| `CandidateRevalidation.java` | Scores safe replay consistency and adjusts candidate classification/confidence based on repeatability |
| `MontoyaResponseEvidence.java` | Caches the calibrated Burp-native semantic baseline profile and records response-variation/keyword evidence |
| `ResponseAnalyzer.java` | Authoritative custom baseline/control scorer, body normalization, redirect `Location` comparison, and false-positive reduction |
| `V8_SMOKE_TEST.md` | Manual release gate for traffic safety, false positives, Burp runtime behavior, evidence quality, and final sign-off |

---

## Execution Safety Profiles

### Safe Mode — default
Use the normal context-menu action:

`Bypass 403 Forbidden (Safe Mode)`

Safe Mode permits automatic technique families only when the selected target method is `GET`, `HEAD`, or `OPTIONS`. If the captured target itself is another method, configuration validation refuses the scan rather than silently replaying it.

Method Tampering remains fully Active-Methods-only because it intentionally creates alternate verbs and method-override payloads.

Header Injection is split at the execution boundary. Header-only mutations that preserve an allowlisted method remain available, including forwarding scheme/port headers, Host variants, Accept variants, and `Upgrade-Insecure-Requests`. POST + Content-Type variants may be generated in memory as part of the same family, but the final pre-queue safety gate rejects them in Safe Mode before they can be transmitted.

### Active Methods — explicit per target
Use:

`Bypass 403 Forbidden (Active Methods...)`

Burp shows a warning before enabling this mode. The researcher must confirm that the target is authorized and that state-changing side effects are understood. Active mode can include `POST`, `PUT`, `PATCH`, `DELETE`, `TRACE`, `CONNECT`, method-override requests, and the POST-based Content-Type header variants.

Active Methods permission applies only to the currently selected target and is intentionally reset when the extension loads or unloads. Cancelling the confirmation keeps Safe Mode active.

---

## Attack Techniques

### 1. IP Spoofing & Header Poisoning
Tests common proxy and client-IP headers such as `X-Forwarded-For`, `X-Custom-IP-Authorization`, `CF-Connecting-IP`, `True-Client-IP`, and `Forwarded` with configurable trusted-looking values.

Selected host-routing headers such as `X-Forwarded-Host`, `X-Host`, `X-Original-Host`, `X-Backend-Host`, and `X-Forwarded-Server` receive routing-surface paired controls when their values are mutated.

### 2. Path Swapping
Tests target-preserving `X-Original-URL` and `X-Rewrite-URL` routing behavior while changing the visible path to `/`.

In v8 these mutations use a paired neutral control:

```text
Denied baseline:  GET /admin -> 403
Control:          GET /      -> 200 homepage
Candidate:        GET / + X-Original-URL: /admin -> 200
```

If candidate and control are effectively the same response, the result is classified as `CONTROL_MATCH` and suppressed as noise. If the candidate materially differs from the control and the denied baseline, that differential evidence can strengthen a `BYPASS_CANDIDATE`.

Dictionary swaps such as testing `/admin` but setting `X-Original-URL: /login` are skipped because they no longer target the protected resource being evaluated.

### 3. Hop-By-Hop Header Abuse
Tests `Connection`-header behaviors involving authorization and proxy-related headers.

### 4. Path Obfuscation
Tests path normalization and encoding variants including dot segments, semicolon forms, double encoding, suffixes, and wildcard-style paths.

### 5. Case Switching
Tests upper, alternating, and segment-capitalized path variants.

### 6. Unicode Normalization
Tests Unicode and encoded path variants that may be normalized differently by frontends and backends.

### 7. Backslash / Normalization
Tests backslash-based path variants relevant to stacks that normalize separators differently.

### 8. Method Tampering & Overrides
Tests alternate methods and method-override headers. This category is Active-Methods-only in v8. Informational method responses are still analyzed conservatively rather than being called bypasses solely because they return `2xx`.

### 9. Protocol Representation Variants — Experimental
This family modifies the HTTP-version token in Burp's request representation before constructing a new Montoya request. It is **disabled by default** and the UI labels it **Experimental**.

Burp owns the HTTP transport stack and can normalize the representation before transmission. Therefore, a result from this family must **not** be described as a verified HTTP/0.9 or HTTP/1.0 wire downgrade unless the actual network behavior has been independently observed and confirmed. The technique description itself states that Burp may normalize the request on send.

This family is retained as an explicitly experimental research aid, not as trustworthy proof of protocol downgrade behavior.

### 10. Suffix Attacks
Tests file-extension, query, fragment-style, and path-suffix variations.

### 11. Header Injection / Routing Hints
Tests forwarding scheme/port headers, Host variants, content types, Accept variants, and related routing hints.

In Safe Mode, header-only requests that preserve `GET`, `HEAD`, or `OPTIONS` can run normally. The four POST + Content-Type mutations are rejected by the final pre-queue method gate. In Active Methods mode, those POST variants become eligible as well.

Direct `Host` mutations are compared on the same mutated routing surface against a deterministic synthetic non-target path. If both the protected target and synthetic control produce the same generic/default-vhost response, the result is suppressed as `CONTROL_MATCH` rather than treated as authorization evidence.

---

## v8 Accuracy Model

403 Forbidden Buster deliberately treats automated results as **candidates**, not confirmed vulnerabilities.

### Calibrated denied baseline
For a captured GET request returning `401` or `403`, the extension sends two unchanged live replays before fuzzing. If the authorization status changes during calibration, the scan is aborted instead of comparing mutations with a stale response.

Dynamic response values such as long numeric IDs, UUIDs, timestamps, and long hexadecimal values are normalized before body similarity comparison.

The same accepted baseline responses are also used to build a cached Burp-native semantic profile. This does **not** add extra baseline requests beyond the existing calibration traffic.

### Paired controls
For supported mutations that can otherwise change the apparent resource or routing surface, v8 uses a paired control designed around the mutation family.

For `X-Original-URL` / `X-Rewrite-URL`, the control preserves the visible carrier path while removing or restoring only the routing mutation. For selected Host/routing mutations, the exact routing mutation is preserved while the protected path is replaced with a deterministic synthetic non-target path. This makes generic virtual-host or catch-all behavior directly measurable.

For paired-control candidates, repeatability testing refreshes the neutral control before every candidate replay. A replay therefore counts only when the **differential itself** remains present.

### Burp-native semantic evidence
Version 8 also uses Montoya's response variation and keyword analyzers as a supplemental evidence layer.

The semantic baseline is built from the captured denied response plus the accepted live calibration responses. Stable/invariant response attributes are learned first. When a candidate is analyzed, v8 reports selected attributes only when the candidate causes an attribute that was stable across the denied baseline to vary. Relevant attributes include status, content type/length, body or visible-text characteristics, word counts, page title, `Location`, `Content-Location`, header/cookie names, ETag, and Last-Modified.

A denial-keyword analyzer follows the same philosophy for terms such as `forbidden`, `access denied`, `unauthorized`, and `permission denied`: normal baseline variation is not treated as new evidence, but a count that moves outside the stable baseline profile is recorded.

When a paired control exists, candidate/control semantic variations are also recorded. This evidence is appended to the Evidence view and exported rationale.

**Important:** the Montoya semantic layer is supplemental. It does not independently create or promote a `BYPASS_CANDIDATE`. The custom baseline/control scorer and repeatability rules remain authoritative.

### Redirect `Location` comparison
Redirects are no longer triaged primarily from status and body length. The `Location` header is explicitly normalized and compared.

Normalization lowercases scheme/host, removes default HTTP/HTTPS ports, drops URL fragments, preserves raw query encoding, and keeps meaningful query differences intact.

Redirect behavior follows these rules:

| Redirect evidence | v8 treatment |
| :--- | :--- |
| Candidate and paired control return the same 3xx status and equivalent non-empty `Location` | `CONTROL_MATCH`, confidence `0`, suppressed |
| Candidate redirects to login/authentication/denial-like destination | `REDIRECT`, confidence capped at `15` |
| Redirect has no usable `Location` | `REDIRECT`, confidence capped at `20` |
| Candidate and control redirect to materially different destinations | Retain `REDIRECT` and add modest differential confidence |
| Control is auth/denial-like but candidate redirects elsewhere | Retain `REDIRECT` with additional manual-inspection signal |

A redirect is **never automatically promoted to `BYPASS_CANDIDATE`** by this logic. It remains a manual-inspection signal because the redirect destination still has to be validated in context.

### Candidate repeatability
A high-signal `GET` candidate is automatically replayed twice after its initial response:

```text
Initial candidate
      ↓
Replay #1
      ↓
Replay #2
      ↓
repeatability verdict
```

A replay counts as consistent only when it remains a `BYPASS_CANDIDATE`, returns the same status as the initial candidate, and its normalized body stays sufficiently similar to the original candidate response.

| Repeatability | Result |
| :--- | :--- |
| `3/3` | Keeps `BYPASS_CANDIDATE`; confidence may increase, capped at 100 |
| `2/3` | Downgraded to `STATUS_ANOMALY`; confidence capped at 55 |
| `1/3` | Downgraded to `STATUS_ANOMALY`; confidence capped at 40 |
| Incomplete replay sequence | Downgraded to `STATUS_ANOMALY`; confidence capped at 50 |

Automatic candidate replay is currently limited to `GET`. Potentially state-changing methods are not automatically repeated; the result records that revalidation was skipped so the researcher can decide how to validate it safely.

### Classification
Results can be classified as:

| Classification | Meaning |
| :--- | :--- |
| `BYPASS_CANDIDATE` | Strong differential evidence; safe GET candidates must also survive automatic repeatability checks |
| `CONTROL_MATCH` | Mutation matched its neutral paired control, including equivalent redirect destinations, and is suppressed as likely noise |
| `REDIRECT` | Denied baseline changed to 3xx; `Location` is triaged but the destination still requires manual authorization validation |
| `METHOD_BEHAVIOR` | Success response came from a method whose semantics commonly differ |
| `BODY_ANOMALY` | Same status but materially different response body |
| `LENGTH_ANOMALY` | Same status but response length falls outside calibrated baseline variance |
| `STATUS_ANOMALY` | Status changed but evidence is insufficient or repeatability was unstable |
| `ERROR` | Server returned 5xx |
| `NORMAL` | No meaningful difference; normally not shown |

### Confidence
Confidence is an evidence score for triage, not a vulnerability severity score and not proof of exploitability. It can increase when the candidate differs substantially from both denied baselines and a neutral control and remains repeatable, and decrease when the response resembles denial/control behavior or fails replay consistency.

---

## Installation

### Prerequisites
* **Java JDK 17+**
* **Burp Suite** (Community or Professional)
* **Gradle**

### Build from Source
1. Clone the repository:
   ```bash
   git clone https://github.com/tobiasGuta/403-Forbidden-Buster.git
   cd 403-Forbidden-Buster/ForbiddenBuster
   ```
2. Build the JAR:
   ```bash
   ./gradlew clean test jar
   ```
3. Load it into Burp Suite:
   * Go to **Extensions** → **Installed**.
   * Click **Add** and select `build/libs/ForbiddenBuster.jar`.

Generated `build/` and `.gradle/` directories are intentionally ignored by Git and are not source-controlled. Release binaries should be built from a recorded commit and published as release artifacts rather than committed into the source tree.

---

## Quick Start

1. Browse to a request that returns `401 Unauthorized` or `403 Forbidden` through Burp Suite.
2. In **Proxy → HTTP History**, right-click the request.
3. Choose **`Bypass 403 Forbidden (Safe Mode)`** for the normal scan. Use **`Active Methods...`** only when the additional request methods are appropriate for the authorized target and confirm the warning.
4. Open the **403 Buster** tab and click **Run Attack**.
5. Review candidate requests, paired controls, and Evidence rationale manually. A high-confidence candidate is not automatically a confirmed authorization bypass.

---

## Attack Controls

| Control | Description |
| :--- | :--- |
| **Run Attack** | Launches the configured scan against the selected target and its selected safety profile |
| **Pause / Resume** | Stops workers before transmission without discarding scan state |
| **Stop** | Prevents interrupted/rate-limited workers from continuing into new sends |
| **Clear Results** | Clears the results table |
| **Export Evidence CSV** | Exports visible evidence-rich results |

---

## Scan Settings

| Setting | Default | Range | Purpose |
| :--- | :--- | :--- | :--- |
| **Execution profile** | Safe Mode | Safe / per-target Active opt-in | Controls whether non-GET/HEAD/OPTIONS families are eligible |
| **Request Delay (ms)** | `50` | 0–2000 in UI | Global delay between transmitted requests |
| **Threads** | `5` | 1–50 | Number of concurrent attack workers |
| **Protocol Representation Variants** | Off | Experimental | Alters the request representation token only; Burp may normalize actual wire protocol behavior |

---

## Release Trust Gate

Before v8 is marked ready for release, run the exact candidate JAR through [`V8_SMOKE_TEST.md`](V8_SMOKE_TEST.md). The checklist covers:

- extension load/defaults and non-persistent Active Methods state;
- calibrated baseline stability and abort behavior;
- path-swap and Host/routing false-positive controls;
- `3/3`, `2/3`, and `1/3` candidate repeatability;
- redirect `Location` handling, including login redirects and raw query encoding;
- Safe Mode request boundaries;
- Pause/Resume/Stop and global rate limiting;
- Candidate / Control / Evidence UI behavior and CSV export;
- Montoya semantic evidence without additional HTTP traffic;
- optional experimental protocol-representation verification.

The Draft PR should not be marked ready until required smoke-test sections pass or every exception is explicitly understood and accepted.

---

## Manual Validation

A `BYPASS_CANDIDATE` means the response has enough differential and repeatability evidence to justify manual inspection. Burp-native semantic variation and automated repeatability still do **not** prove that the response exposes the intended protected resource, data, or action. Before reporting a vulnerability, validate those protected semantics manually and remain within the authorized testing scope.

---

## Disclaimer
This tool is for educational purposes and authorized security testing only. Do not use it on systems you do not have permission to test. The author is not responsible for misuse.

---

<div align="center">
  <h3>☕ Support My Journey</h3>
</div>

<div align="center">
  <a href="https://www.buymeacoffee.com/tobiasguta">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" width="200" />
  </a>
</div>
