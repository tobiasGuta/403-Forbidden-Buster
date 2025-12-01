# 403 Forbidden Buster (Burp Suite Extension)

**An Automated 403 Bypass Fuzzer for Burp Suite Community & Professional**

![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white) ![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=for-the-badge&logo=burpsuite&logoColor=white) ![Security](https://img.shields.io/badge/Cybersecurity-Bug_Bounty-red?style=for-the-badge)

## Overview
**403 Forbidden Buster** is a Burp Suite extension designed to automate the process of bypassing `403 Forbidden` and `401 Unauthorized` endpoints.

When a security professional encounters a restricted page (e.g., `/admin` or `/api/private`), manually testing every bypass technique is time-consuming. This extension allows the user to right-click the request and immediately launch a background scan using the most common and effective bypass heuristics.

Unlike Burp Intruder, this extension runs in its own thread pool, bypassing the throttling limitations of Burp Suite Community Edition.

## Features

### 1. Automated Heuristic Fuzzing
The extension attempts 50+ variations of the original request using four main strategies:
* **Header Poisoning:** Injects headers known to confuse reverse proxies (e.g., `X-Custom-IP-Authorization`, `X-Forwarded-For`) with trusted values like `127.0.0.1`.
* **Path Manipulation:** Modifies the URL path to trick ACLs (e.g., `/%2e/admin`, `/admin/.`, `/admin;`, `/admin//`).
* **Method Tampering:** Attempts to access the resource using alternate HTTP methods (`POST`, `TRACE`, `HEAD`).
* **Referer Spoofing:** specific logic to bypass Referer-based access controls.

### 2. Smart False Positive Detection
* **Path Swapping:** When testing headers like `X-Original-URL`, the tool automatically swaps the request path to `/` (root) while placing the target path in the header.
* **Baseline Comparison:** To prevent false positives where the server ignores the header and returns the homepage (200 OK), the tool compares the response length against a baseline request. If the content matches the homepage, the result is discarded.

### 3. Dynamic Referer Generation
The tool builds a dynamic list of Referer headers to bypass "Deep Linking" protections:
* **Self-Reference:** Sets the Referer to the current full URL.
* **Root Reference:** Sets the Referer to the homepage.
* **Directory Walking:** Automatically calculates parent directories from the current path.
* **Dictionary Attack:** Tries common parents such as `/admin`, `/dashboard`, `/login`, and `/internal`. You can add more entries to this list by modifying the source code and rebuilding the extension.

### 4. Professional UI Dashboard
Results are displayed in a dedicated **"403 Buster"** tab.
* **Master-Detail View:** Clicking any result row instantly displays the full **Request** and **Response** in a split-pane editor.
* **Filtering:** The tool only logs successful bypasses (non-403/401 statuses), keeping the view clean.
* **Context Menu:** Right-click rows to **Delete Item** or **Clear History**.

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
