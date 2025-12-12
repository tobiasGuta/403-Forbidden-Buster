# 403 Forbidden Buster (Burp Suite Extension)

**An Automated 403 Bypass Fuzzer for Burp Suite Community & Professional**

![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white) ![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=for-the-badge&logo=burpsuite&logoColor=white) ![Security](https://img.shields.io/badge/Cybersecurity-Bug_Bounty-red?style=for-the-badge)

## Overview
**403 Forbidden Buster** is a Burp Suite extension designed to automate the process of bypassing `403 Forbidden` and `401 Unauthorized` endpoints.

When a security professional encounters a restricted page (e.g., `/admin` or `/api/private`), manually testing every bypass technique is time-consuming. This extension allows the user to right-click the request and immediately launch a background scan using the most common and effective bypass heuristics.

Unlike Burp Intruder, this extension runs in its own thread pool, bypassing the throttling limitations of Burp Suite Community Edition.

## Features

## Features

### 1. Automated Heuristic Fuzzing
The extension attempts **100+ variations** of the original request using advanced evasion strategies:
* **Header Poisoning:** Injects headers known to confuse reverse proxies (e.g., `X-Custom-IP-Authorization`, `X-Forwarded-For`, `X-Original-URL`) with trusted values like `127.0.0.1` and `localhost`.
* **Protocol Downgrade:** Automatically attempts to downgrade the request to **HTTP/1.0**. This is a critical technique for bypassing WAFs and Load Balancers (like HAProxy/Nginx) that only apply strict rules to HTTP/1.1 traffic.
* **Port & Protocol Spoofing:** Manipulates the `Host` header and connection properties to simulate internal administrative traffic.

### 2. Proxy & Gateway Manipulation
* **Hop-by-Hop Header Abuse:** Leverages the HTTP `Connection` header to force intermediate proxies to **strip** critical access-control headers (e.g., `Cookie`, `Authorization`, `X-Forwarded-For`) before the request reaches the backend. This effectively makes the backend treat the request as "clean" or "internal."

### 3. Advanced Path & Obfuscation
Going beyond simple path traversal, the tool now includes complex encoding and normalization exploits:
* **Case Switching:** Automatically toggles path casing (e.g., `/admin` -> `/ADMIN`) to bypass case-sensitive WAF rules, particularly effective against IIS and Java servers.
* **Deep Obfuscation:** Uses **Double URL Encoding** (`%252e`) and **Unicode Variations** (`%ef%bc%8f`) to bypass normalization filters.
* **Magic Suffixes & Extensions:** Appends "trusted" extensions and characters to the path (e.g., `.json`, `.css`, `;jsessionid=1337`, `?.png`) to trick ACLs into treating the request as a static resource.

### 4. Method Tampering & Overrides
* **Verb Switching:** Attempts to access the resource using alternate HTTP methods (`POST`, `TRACE`, `HEAD`).
* **Method Overrides:** Automatically injects headers like `X-HTTP-Method-Override: GET` while sending a `POST` request, often bypassing GET-based blocking rules.

### 5. Smart False Positive Detection
* **Path Swapping:** When testing headers like `X-Original-URL`, the tool automatically swaps the request path to `/` (root) while placing the target path in the header.
* **Baseline Comparison:** To prevent false positives where the server ignores the header and returns the homepage (200 OK), the tool compares the response length against a baseline request. If the content matches the homepage, the result is discarded.

### 6. Dynamic Referer Generation
The tool builds a dynamic list of Referer headers to bypass "Deep Linking" protections:
* **Self-Reference:** Sets the Referer to the current full URL.
* **Root Reference:** Sets the Referer to the homepage.
* **Directory Walking:** Automatically calculates parent directories from the current path.
* **Dictionary Attack:** Uses the configurable wordlist to inject common parents (e.g., `/admin`, `/dashboard`) into the Referer header.

### 7. Tabbed Professional Dashboard
Results are displayed in a dedicated **"403 Buster"** suite tab with a split interface:
* **Monitor Tab:** A real-time table of results. Clicking any row instantly displays the full **Request** and **Response** in a split-pane editor.
* **Configuration Tab:** A dedicated area to manage your wordlists and settings on the fly.

### 8. Customization & Stealth (New)
* **Fully Configurable Wordlists:** You can now edit the **IP Spoofing List** and **Path Dictionary** directly within the UI. Add custom internal IPs or specific paths you want to fuzz.
* **Smart Persistence:** The extension automatically **saves your configuration**, preserving your custom wordlists and settings between Burp Suite restarts.
* **Rate Limiting:** Includes a configurable **Request Delay Slider** (0ms - 1000ms). This allows you to slow down the attack to avoid triggering **429 Too Many Requests** or getting IP banned by aggressive WAFs like Cloudflare or Akamai.

<img width="1908" height="819" alt="image" src="https://github.com/user-attachments/assets/189fd245-e0b7-490f-ba30-76aaad4c86e0" />

<img width="1911" height="850" alt="image" src="https://github.com/user-attachments/assets/cbd87af7-2475-4616-a034-e27556c52d2e" />

## Installation

### Prerequisites
* Java Development Kit (JDK) 21.
* Burp Suite (Community or Professional).
* Gradle.

### Build from Source
1.  Clone the repository:
    ```bash
    git clone https://github.com/tobiasGuta/403-Forbidden-Buster.git
    cd 403-Forbidden-Buster
    ```
2.  Build the JAR file:
    ```bash
    ./gradlew clean jar
    ```
3.  Load into Burp Suite:
    * Navigate to **Extensions** -> **Installed**.
    * Click **Add** -> Select `build/libs/ForbiddenBuster.jar`.

## Usage Guide

1.  **Identify a Target:** Browse to a URL that returns a `403 Forbidden` status.
2.  **Launch Attack:**
    * Go to **Proxy** -> **HTTP History**.
    * Right-click the 403 request.
    * Select **Bypass 403 Forbidden**.
3.  **Analyze Results:**
    * Open the **"403 Buster"** tab.
    * Wait for results to appear.
    * Click on a row to inspect the response.
    * **Note:** The tool logs `200 OK`, `302 Found`, `404 Not Found`, and `500 Error`. It filters out `403` and `401`.

## Tech Stack
* **Language:** Java 21
* **API:** Burp Suite Montoya API
* **UI Components:** Swing (JTable, JSplitPane, Burp Native Editors)

## Disclaimer
This tool is for educational purposes and authorized security testing only. Do not use this tool on systems you do not have permission to test. The author is not responsible for any misuse.

# Support
If my tool helped you land a bug bounty, consider buying me a coffee ☕️ as a small thank-you! Everything I build is free, but a little support helps me keep improving and creating more cool stuff ❤️
---

<div align="center">
  <h3>☕ Support My Journey</h3>
</div>


<div align="center">
  <a href="https://www.buymeacoffee.com/tobiasguta">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" width="200" />
  </a>
</div>
