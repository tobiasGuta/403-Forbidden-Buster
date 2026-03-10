# 403 Forbidden Buster (Burp Suite Extension)

**An Automated 403 Bypass Fuzzer for Burp Suite Community & Professional**

![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white) ![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=for-the-badge&logo=burpsuite&logoColor=white) ![Security](https://img.shields.io/badge/Cybersecurity-Bug_Bounty-red?style=for-the-badge)

## Overview
**403 Forbidden Buster** is a Burp Suite extension designed to automate the process of bypassing `403 Forbidden` and `401 Unauthorized` endpoints.

When a security professional encounters a restricted page (e.g., `/admin` or `/api/private`), manually testing every bypass technique is time-consuming. This extension allows the user to right-click the request and immediately launch a background scan using the most common and effective bypass heuristics.

Unlike Burp Intruder, this extension runs in its own thread pool, bypassing the throttling limitations of Burp Suite Community Edition.

---

## Key Features
* **150+ Bypass Techniques:** Automated fuzzing with header poisoning, path obfuscation, method tampering, protocol downgrade, Unicode normalization, backslash tricks, and more.
* **Attack Controls:** Pause, resume, and stop attacks on demand — full control over traffic generation.
* **Progress Bar:** Real-time completion tracking for long-running scans.
* **CSV Export:** Export the full results table to CSV for reporting and further analysis.
* **Global Rate Limiting:** Enforced across all threads — the delay you set is the actual delay between requests.
* **Input Validation:** All fields are validated before attacks launch, with clear error messages.
* **Color-Coded Results:** Instant visual triage — green for bypasses, orange for redirects, red for server errors.
* **Native Burp UI:** Split-pane Request/Response editors for professional traffic analysis.
* **Persistent Configuration:** All settings saved across Burp restarts.

---

## Architecture

The extension follows a modular architecture with clean separation of concerns:

| File | Responsibility |
| :--- | :--- |
| `ForbiddenBuster.java` | Entry point — registers extension, tab, context menu, unload handler |
| `BusterUI.java` | All Swing UI, event handling, persistence, CSV export, color-coded table |
| `AttackEngine.java` | Thread pool management, pause/resume/stop, global rate limiting |
| `AttackConfig.java` | Immutable configuration holder with input validation |
| `BypassResult.java` | Data class for storing attack result entries |
| `PayloadGenerator.java` | Generates 150+ bypass payloads across 11 attack categories |
| `ResponseAnalyzer.java` | Smart false-positive detection, baseline comparison, result classification |

---

## Attack Techniques (11 Categories)

### 1. IP Spoofing & Header Poisoning
Injects 23+ headers known to confuse reverse proxies (`X-Forwarded-For`, `X-Custom-IP-Authorization`, `CF-Connecting-IP`, `True-Client-IP`, `Forwarded`, etc.) with trusted values like `127.0.0.1` and `localhost`.

### 2. Path Swapping
When testing headers like `X-Original-URL` and `X-Rewrite-URL`, the tool swaps the request path to `/` (root) while placing the target path in the header. Includes dictionary-based swapping.

### 3. Hop-By-Hop Header Abuse
Leverages the HTTP `Connection` header to force intermediate proxies to **strip** critical access-control headers (`Cookie`, `Authorization`, `X-Api-Key`, `X-Auth-Token`) before the request reaches the backend.

### 4. Path Obfuscation
18+ prefix techniques (`/./`, `/;/`, `/.;/`, `/..;/`, `/%2e/`, `/%252e/`, `/%ef%bc%8f`) plus inline suffix tricks, double URL encoding, Tomcat/Spring `..;` traversal, and wildcard paths.

### 5. Case Switching
Toggles path casing — UPPER, alternating case, and capitalized segments — to bypass case-sensitive WAF rules (effective against IIS, Java, and .NET servers).

### 6. Unicode Normalization Bypass
12 Unicode and overlong UTF-8 variants including fullwidth solidus (`U+FF0F`), division slash (`U+2215`), fullwidth full stop (`U+FF0E`), IIS unicode dots (`%u002e`), and overlong sequences (`%c0%af`, `%e0%80%af`).

### 7. Backslash Bypass (IIS/Tomcat)
9 backslash-based payloads — `\`, `\..\ `, `%5c`, `%5c..%5c` — effective against IIS, Tomcat, and Spring servers that normalize backslashes differently.

### 8. Method Tampering & Overrides
Tests 9 HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`, `TRACE`, `HEAD`, `OPTIONS`, `CONNECT`) plus 5 override headers (`X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`, `X-Original-Method`, `_method`) crossed with 4 target methods.

### 9. Protocol Downgrade
Automatically downgrades the request to `HTTP/0.9` and `HTTP/1.0` — critical for bypassing WAFs and load balancers that only apply rules to HTTP/1.1 traffic.

### 10. Suffix Attacks
26+ suffix payloads including file extensions (`.json`, `.css`, `.xml`, `.txt`), query tricks (`?`, `??`, `%3f`), fragment injection (`#`, `%23`), and session IDs (`;jsessionid=1337`).

### 11. Header Injection (Proto/Port/Host)
Spoofs `X-Forwarded-Proto`, `X-Forwarded-Scheme`, `X-Forwarded-Port`, `Host` header manipulation, `Content-Type` fuzzing on POST, `Accept` header variants, and `Upgrade-Insecure-Requests`.

---

## Smart False Positive Detection

* **Baseline Comparison:** Every result is compared against the original response. Only status code changes or significant body length differences (>10% or >100 bytes) are shown.
* **Result Classification:** Responses are classified as BYPASS (4xx→2xx), REDIRECT (4xx→3xx), LENGTH_ANOMALY, ERROR (5xx), or NORMAL.
* **Configurable Filters:** Hide 403s, hide 404s, or both — focus on what matters.

---

## Dynamic Referer Generation

* **Self-Reference:** Sets the Referer to the current full URL.
* **Root Reference:** Sets the Referer to the homepage.
* **Directory Walking:** Automatically calculates parent directories from the current path.
* **Dictionary Attack:** Uses the configurable path list to inject common parents into the Referer header.

---

## Installation

### Prerequisites
* **Java JDK 17+**
* **Burp Suite** (Community or Professional)
* **Gradle**

### Build from Source
1.  Clone the repository:
    ```bash
    git clone https://github.com/tobiasGuta/403-Forbidden-Buster.git
    cd 403-Forbidden-Buster/ForbiddenBuster
    ```
2.  Build the JAR file:
    ```bash
    ./gradlew clean jar
    ```
3.  Load into Burp Suite:
    * Navigate to **Extensions** → **Installed**.
    * Click **Add** → Select `build/libs/ForbiddenBuster.jar`.

---

## Quick Start

1.  Browse to a URL that returns `403 Forbidden` through Burp Suite's Proxy.
2.  In **Proxy → HTTP History**, right-click the 403 request and select **"Bypass 403 Forbidden"**.
3.  The **"403 Buster"** tab will activate with the target set. Click **Run Attack**.
4.  Monitor results in real-time. Click any row to inspect the full request/response.

---

## Attack Controls

| Control | Description |
| :--- | :--- |
| **Run Attack** | Launches the full bypass scan against the selected target. |
| **Pause / Resume** | Temporarily halts the attack without losing progress. |
| **Stop** | Completely terminates the current attack. |
| **Clear Results** | Clears the results table. |
| **Export CSV** | Exports results to a CSV file for reporting. |

A **progress bar** shows real-time completion status during attacks.

---

## Scan Settings

| Setting | Default | Range | Purpose |
| :--- | :--- | :--- | :--- |
| **Request Delay (ms)** | `50` | 0–2000 | Global delay between requests. Enforced across all threads. |
| **Threads** | `5` | 1–50 | Number of concurrent attack threads. |

---

## Interpreting Results

| Status Range | Color | Meaning |
| :--- | :--- | :--- |
| **2xx** | Green | Potential bypass — the server returned a success response. |
| **3xx** | Orange | Redirect — may indicate a bypass via redirection. |
| **5xx** | Red | Server error — worth investigating for edge cases. |
| **Other** | White | Normal response, logged due to length anomaly. |

The **Length** column helps identify interesting responses — length anomalies across techniques often indicate partial bypasses or information disclosure.

---

## Disclaimer
This tool is for educational purposes and authorized security testing only. Do not use this tool on systems you do not have permission to test. The author is not responsible for any misuse.

---

<div align="center">
  <h3>☕ Support My Journey</h3>
</div>


<div align="center">
  <a href="https://www.buymeacoffee.com/tobiasguta">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" width="200" />
  </a>
</div>
