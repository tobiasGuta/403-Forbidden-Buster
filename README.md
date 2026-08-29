# 403 Forbidden Buster (Burp Suite Extension)

**An Automated 403 Bypass Fuzzer for Burp Suite Community & Professional**

![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white) ![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=for-the-badge&logo=burpsuite&logoColor=white) ![Security](https://img.shields.io/badge/Cybersecurity-Bug_Bounty-red?style=for-the-badge)

## Overview
**403 Forbidden Buster** is a Burp Suite extension designed to automate testing of `403 Forbidden` and `401 Unauthorized` endpoints.

When a security professional encounters a restricted page (for example `/admin` or `/api/private`), manually testing every bypass technique is time-consuming. This extension allows the user to right-click the captured Burp request and launch a background scan using common bypass heuristics while preserving the original request context.

Version 8 is accuracy- and safety-focused. A status change alone is not treated as proof of an authorization bypass. Results are compared with calibrated denied baselines, neutral paired controls where appropriate, and safe repeatability checks for high-signal GET candidates. Safe Mode is the default execution profile; non-GET/HEAD/OPTIONS request families require a per-target Active Methods opt-in.

---

## Key Features
* **150+ Bypass Techniques:** Automated fuzzing with header poisoning, path obfuscation, method tampering, protocol variants, Unicode normalization, backslash tricks, and more.
* **Safe Mode by Default:** Automatic transmission is limited to GET/HEAD/OPTIONS technique families. Non-allowlisted methods are gated behind an explicit per-target confirmation and are never persisted as the default.
* **Calibrated Baselines:** Safe GET targets are replayed before fuzzing to learn normal response variance and reject stale authorization baselines.
* **Paired Differential Controls:** Target-preserving `X-Original-URL` and `X-Rewrite-URL` path swaps are compared with the same visible request minus the routing mutation so a normal root-page `200` is not mistaken for a bypass.
* **Semantic-Target Guard:** Dictionary path swaps that point at a different resource are skipped instead of being scored as target bypasses.
* **Safe Candidate Revalidation:** High-signal GET candidates are replayed twice. Only a stable `3/3` result retains `BYPASS_CANDIDATE`; paired-control techniques receive a fresh neutral control on every replay.
* **Evidence-Based Classification:** Status, method semantics, normalized body similarity, denial markers, body length, paired-control differences, and repeatability contribute to candidate confidence.
* **Attack Controls:** Pause, resume, and stop attacks on demand. Queued workers respect pause, and Stop acts as a send barrier.
* **Progress Bar:** Real-time completion tracking for long-running scans.
* **CSV Export:** Export the results table to CSV for reporting and further analysis.
* **Global Rate Limiting:** Enforced across baseline calibration, paired controls, candidate revalidation, and attack requests.
* **Native Burp UI:** Split-pane Request/Response editors for manual validation.
* **Persistent Configuration:** Ordinary scan settings are saved across Burp restarts. Active Methods permission is intentionally not persisted.

---

## Architecture

The extension follows a modular architecture with clean separation of concerns:

| File | Responsibility |
| :--- | :--- |
| `ForbiddenBuster.java` | Entry point — registers extension, tab, Safe/Active context-menu actions, unload handler |
| `BusterUI.java` | Swing UI, event handling, persistence, CSV export, result table |
| `AttackEngine.java` | Baseline calibration, paired-control execution, safe candidate revalidation, thread management, pause/resume/stop, global rate limiting |
| `AttackConfig.java` | Immutable configuration plus effective Safe Mode technique gates |
| `ActiveMethodsRegistry.java` | Stores the current target's ephemeral Safe/Active execution choice; never persisted |
| `RequestSafetyPolicy.java` | Central GET/HEAD/OPTIONS automatic-method allowlist |
| `BypassResult.java` | Stores candidate evidence, classification, confidence, paired-control evidence, and repeatability metadata |
| `PayloadGenerator.java` | Generates bypass payloads from the effective technique configuration |
| `PairedControlPlanner.java` | Enforces semantic-target invariants and creates neutral paired controls for supported mutations |
| `CandidateRevalidation.java` | Scores safe replay consistency and adjusts candidate classification/confidence based on repeatability |
| `ResponseAnalyzer.java` | Baseline/control differential analysis and false-positive reduction |

---

## Execution Safety Profiles

### Safe Mode — default
Use the normal context-menu action:

`Bypass 403 Forbidden (Safe Mode)`

Safe Mode permits automatic technique families only when the selected target method is `GET`, `HEAD`, or `OPTIONS`. If the captured target itself is another method, configuration validation refuses the scan rather than silently replaying it.

The current Method Tampering category and the current Header Injection category are completely gated in Safe Mode because those generator families contain non-allowlisted requests. Other header-, path-, normalization-, protocol-, suffix-, and routing-oriented families remain available when they preserve an allowlisted target method.

### Active Methods — explicit per target
Use:

`Bypass 403 Forbidden (Active Methods...)`

Burp shows a warning before enabling this mode. The researcher must confirm that the target is authorized and that state-changing side effects are understood. Active mode can include `POST`, `PUT`, `PATCH`, `DELETE`, `TRACE`, `CONNECT`, and method-override requests.

Active Methods permission applies only to the currently selected target and is intentionally reset when the extension loads or unloads. Cancelling the confirmation keeps Safe Mode active.

---

## Attack Techniques

### 1. IP Spoofing & Header Poisoning
Tests common proxy and client-IP headers such as `X-Forwarded-For`, `X-Custom-IP-Authorization`, `CF-Connecting-IP`, `True-Client-IP`, and `Forwarded` with configurable trusted-looking values.

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
Tests alternate methods and method-override headers. This category is Active-Methods-only in v8 Slice 4. Informational method responses are still analyzed conservatively rather than being called bypasses solely because they return `2xx`.

### 9. Protocol Variants
Tests request-version mutations. Protocol behavior should still be manually validated because the HTTP stack can normalize requests before transmission.

### 10. Suffix Attacks
Tests file-extension, query, fragment-style, and path-suffix variations.

### 11. Header Injection / Routing Hints
Tests forwarding scheme/port headers, Host variants, content types, Accept variants, and related routing hints. The current category also contains POST-based Content-Type variants, so the whole category is gated behind Active Methods until the generator is split into safe and active subfamilies. This is a conservative safety choice, not a claim that every header mutation is state-changing.

---

## v8 Accuracy Model

403 Forbidden Buster deliberately treats automated results as **candidates**, not confirmed vulnerabilities.

### Calibrated denied baseline
For a captured GET request returning `401` or `403`, the extension sends two unchanged live replays before fuzzing. If the authorization status changes during calibration, the scan is aborted instead of comparing mutations with a stale response.

Dynamic response values such as long numeric IDs, UUIDs, timestamps, and long hexadecimal values are normalized before body similarity comparison.

### Paired controls
For supported mutations that intentionally change the visible request target, v8 sends a neutral paired control that preserves the same visible request while removing or restoring only the routing mutation. This helps distinguish a real routing differential from the normal response of the visible path.

For paired-control candidates, repeatability testing refreshes the neutral control before every candidate replay. A replay therefore counts only when the **differential itself** remains present.

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
| `CONTROL_MATCH` | Mutation matched its neutral paired control and is suppressed as likely noise |
| `REDIRECT` | Denied baseline changed to 3xx; redirect destination requires inspection |
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

---

## Quick Start

1. Browse to a request that returns `401 Unauthorized` or `403 Forbidden` through Burp Suite.
2. In **Proxy → HTTP History**, right-click the request.
3. Choose **`Bypass 403 Forbidden (Safe Mode)`** for the normal scan. Use **`Active Methods...`** only when the additional request methods are appropriate for the authorized target and confirm the warning.
4. Open the **403 Buster** tab and click **Run Attack**.
5. Review candidate requests and responses manually. A high-confidence candidate is not automatically a confirmed authorization bypass.

---

## Attack Controls

| Control | Description |
| :--- | :--- |
| **Run Attack** | Launches the configured scan against the selected target and its selected safety profile |
| **Pause / Resume** | Stops workers before transmission without discarding scan state |
| **Stop** | Prevents interrupted/rate-limited workers from continuing into new sends |
| **Clear Results** | Clears the results table |
| **Export CSV** | Exports visible results |

---

## Scan Settings

| Setting | Default | Range | Purpose |
| :--- | :--- | :--- | :--- |
| **Execution profile** | Safe Mode | Safe / per-target Active opt-in | Controls whether non-GET/HEAD/OPTIONS families are eligible |
| **Request Delay (ms)** | `50` | 0–2000 in UI | Global delay between transmitted requests |
| **Threads** | `5` | 1–50 | Number of concurrent attack workers |

---

## Manual Validation

A `BYPASS_CANDIDATE` means the response has enough differential and repeatability evidence to justify manual inspection. Automated repeatability still does **not** prove that the response exposes the intended protected resource, data, or action. Before reporting a vulnerability, validate those protected semantics manually and remain within the authorized testing scope.

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
