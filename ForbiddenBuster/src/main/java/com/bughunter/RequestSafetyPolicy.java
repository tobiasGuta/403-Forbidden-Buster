package com.bughunter;

import java.util.Locale;
import java.util.Set;

/**
 * Central v8 policy for deciding which HTTP methods are eligible for automatic
 * transmission while Safe Mode is enabled.
 */
final class RequestSafetyPolicy {

    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");

    private RequestSafetyPolicy() {}

    static boolean isSafeAutomaticMethod(String method) {
        if (method == null) return false;
        return SAFE_METHODS.contains(method.trim().toUpperCase(Locale.ROOT));
    }
}
