# 403 Forbidden Buster (Burp Suite Extension)

**An Automated 403 Bypass Fuzzer for Burp Suite Community & Professional**

![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white) ![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=for-the-badge&logo=burpsuite&logoColor=white) ![Security](https://img.shields.io/badge/Cybersecurity-Bug_Bounty-red?style=for-the-badge)

## Overview
**403 Forbidden Buster** is a Burp Suite extension designed to automate testing of `403 Forbidden` and `401 Unauthorized` endpoints.

When a security professional encounters a restricted page (for example `/admin` or `/api/private`), manually testing every bypass technique is time-consuming. This extension allows the user to right-click the captured Burp request and launch a background scan using common bypass heuristics while preserving the original request context.

Version 8 is accuracy-focused. A status change alone is not treated as proof of an authorization bypass. Results are compared with calibrated denied baselines and, where a mutation changes the visible request target, neutral paired controls.

---

## Key Features
* **150+ Bypass Techniques:** Automated fuzzing with header poisoning, path obfuscation, method tampering, protocol variants, Unicode normalization, backslash tricks, and more.
* **Calibrated Baselines:** Safe GET targets are replayed before fuzzing to learn normal response variance and reject stale authorization baselines.
* **Paired Differential Controls:** Target-preserving `X-Original-URL` and `X-Rewrite-URL` path swaps are compared with the same visible request minus the routing mutation so a normal root-page `200` is not mistaken for a bypass.
* **Semantic-Target Guard:** Dictionary path swaps that point at a different resource are skipped instead of being scored as target bypasses.
* **Evidence-Based Classification:** Status, method semantics, normalized body similarity, denial markers, body length, and paired-control differences contribute to candidate confidence.
* **Attack Controls:** Pause, resume, and stop attacks on demand. Queued workers respect pause, and Stop acts as a send barrier.
* **Progress Bar:** Real-time completion tracking for long-running scans.
* **CSV Export:** Export the results table to CSV for reporting and further analysis.
* **Global Rate Limiting:** Enforced across baseline calibration, paired controls, and attack requests.
* **Native Burp UI:** Split-pane Request/Response editors for manual validation.
* **Persistent Configuration:** Settings are saved across Burp restarts.

---

## Architecture

The extension follows a modular architecture with clean separation of concerns:

| File | Responsibility |
| :--- | :--- |
| `ForbiddenBuster.java` | Entry point — registers extension, tab, context menu, unload handler |
| `BusterUI.java` | Swing UI, event handling, persistence, CSV export, result table |
| `AttackEngine.java` | Baseline calibration, paired-control execution, thread management, pause/resume/stop, global rate limiting |
| `AttackConfig.java` | Immutable configuration holder with input validation |
| `BypassResult.java` | Stores candidate evidence, classification, confidence, and optional paired-control evidence |
| `PayloadGenerator.java` | Generates bypass payloads across attack categories |
| `PairedControlPlanner.java` | Enforces semantic-target invariants and creates neutral paired controls for supported mutations |
| `ResponseAnalyzer.java` | Baseline/control differential analysis and false-positive reduction |

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
Tests alternate methods and method-override headers. Informational methods such as `HEAD` and `OPTIONS` are not automatically treated as bypasses merely because they return `2xx`.

### 9. Protocol Variants
Tests request-version mutations. Protocol behavior should still be manually validated because the HTTP stack can normalize requests before transmission.

### 10. Suffix Attacks
Tests file-extension, query, fragment-style, and path-suffix variations.

### 11. Header Injection / Routing Hints
Tests forwarding scheme/port headers, Host variants, content types, Accept variants, and related routing hints.

---

## v8 Accuracy Model

403 Forbidden Buster deliberately treats automated results as **candidates**, not confirmed vulnerabilities.

### Calibrated denied baseline
For a captured GET request returning `401` or `403`, the extension sends two unchanged live replays before fuzzing. If the authorization status changes during calibration, the scan is aborted instead of comparing mutations with a stale response.

Dynamic response values such as long numeric IDs, UUIDs, timestamps, and long hexadecimal values are normalized before body similarity comparison.

### Classification
Results can be classified as:

| Classification | Meaning |
| :--- | :--- |
| `BYPASS_CANDIDATE` | Strong differential evidence; still requires manual authorization validation |
| `CONTROL_MATCH` | Mutation matched its neutral paired control and is suppressed as likely noise |
| `REDIRECT` | Denied baseline changed to 3xx; redirect destination requires inspection |
| `METHOD_BEHAVIOR` | Success response came from a method whose semantics commonly differ, such as HEAD/OPTIONS |
| `BODY_ANOMALY` | Same status but materially different response body |
| `LENGTH_ANOMALY` | Same status but response length falls outside calibrated baseline variance |
| `STATUS_ANOMALY` | Status changed but evidence is insufficient for a strong bypass candidate |
| `ERROR` | Server returned 5xx |
| `NORMAL` | No meaningful difference; normally not shown |

### Confidence
Confidence is an evidence score for triage, not a vulnerability severity score and not proof of exploitability. It can increase when the candidate differs substantially from both denied baselines and a neutral control, and decrease when the response resembles denial/control behavior.

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
2. In **Proxy → HTTP History**, right-click the request and select **"Bypass 403 Forbidden"**.
3. Open the **403 Buster** tab and click **Run Attack**.
4. Review candidate requests and responses manually. A high-confidence candidate is not automatically a confirmed authorization bypass.

---

## Attack Controls

| Control | Description |
| :--- | :--- |
| **Run Attack** | Launches the configured scan against the selected target |
| **Pause / Resume** | Stops workers before transmission without discarding scan state |
| **Stop** | Prevents interrupted/rate-limited workers from continuing into new sends |
| **Clear Results** | Clears the results table |
| **Export CSV** | Exports visible results |

---

## Scan Settings

| Setting | Default | Range | Purpose |
| :--- | :--- | :--- | :--- |
| **Request Delay (ms)** | `50` | 0–2000 in UI | Global delay between transmitted requests |
| **Threads** | `5` | 1–50 | Number of concurrent attack workers |

---

## Manual Validation

A `BYPASS_CANDIDATE` means the response has enough differential evidence to justify manual inspection. Before reporting a vulnerability, verify that the response actually exposes the protected resource, data, or action and that the behavior is repeatable within the authorized testing scope.

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
