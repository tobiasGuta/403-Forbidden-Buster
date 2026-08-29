package com.bughunter;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Locale;
import java.util.Set;

/**
 * Central v8 policy for deciding which HTTP requests may be transmitted
 * automatically while Safe Mode is enabled.
 */
final class RequestSafetyPolicy {

    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");
    private static final String[] METHOD_OVERRIDE_HEADERS = {
            "X-HTTP-Method-Override",
            "X-HTTP-Method",
            "X-Method-Override",
            "X-Original-Method",
            "_method"
    };

    private RequestSafetyPolicy() {}

    static boolean maySendAutomatically(HttpRequest request, AttackConfig config) {
        if (config.isActiveMethodsEnabled()) return true;
        if (request == null) return false;
        if (!isSafeAutomaticMethod(request.method())) return false;

        for (String header : METHOD_OVERRIDE_HEADERS) {
            String override = request.headerValue(header);
            if (override != null && !override.isBlank() && !isSafeAutomaticMethod(override)) {
                return false;
            }
        }
        return true;
    }

    static boolean isSafeAutomaticMethod(String method) {
        if (method == null) return false;
        return SAFE_METHODS.contains(method.trim().toUpperCase(Locale.ROOT));
    }

    static String describeMode(AttackConfig config) {
        return config.isActiveMethodsEnabled()
                ? "ACTIVE METHODS enabled"
                : "SAFE MODE (GET/HEAD/OPTIONS only)";
    }
}
