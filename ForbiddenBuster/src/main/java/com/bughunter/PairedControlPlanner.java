package com.bughunter;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Plans neutral paired controls for mutations that can otherwise produce false
 * positives by changing the visible resource or routing surface. It also acts
 * as the final pre-queue Safe Mode gate.
 */
final class PairedControlPlanner {

    private static final String PATH_SWAPPING = "Path Swapping";
    private static final String HEADER_INJECTION = "Header Injection";
    private static final String IP_SPOOFING = "IP Spoofing";

    private static final String[] PATH_SWAP_HEADERS = {"X-Original-URL", "X-Rewrite-URL"};

    /**
     * Host-like headers that can select a different virtual host, upstream, or
     * routing surface. These need a different control from path swapping: the
     * routing mutation is preserved while the protected path is replaced with a
     * deterministic synthetic path. A generic/default-vhost 200 should then
     * match the control instead of looking like protected-resource access.
     */
    private static final Set<String> ROUTING_HEADERS = Set.of(
            "host",
            "x-forwarded-host",
            "x-host",
            "x-original-host",
            "x-backend-host",
            "x-forwarded-server"
    );

    private PairedControlPlanner() {}

    static Plan plan(HttpRequestResponse baseline, PayloadGenerator.Payload payload) {
        if (!RequestSafetyPolicy.isAllowedByCurrentMode(payload.request.method())) {
            return Plan.skip(
                    "Safe Mode blocked non-allowlisted method " + payload.request.method()
            );
        }

        if (PATH_SWAPPING.equals(payload.category)) {
            return planPathSwap(baseline, payload);
        }

        if (HEADER_INJECTION.equals(payload.category) || IP_SPOOFING.equals(payload.category)) {
            Plan routingPlan = planRoutingSurfaceControl(baseline, payload);
            if (routingPlan.action() != Action.NONE) return routingPlan;
        }

        return Plan.none();
    }

    private static Plan planPathSwap(HttpRequestResponse baseline, PayloadGenerator.Payload payload) {
        String originalTarget = baseline.request().path();
        for (String header : PATH_SWAP_HEADERS) {
            String originalHeaderValue = baseline.request().headerValue(header);
            String candidateHeaderValue = payload.request.headerValue(header);

            // Ignore pre-existing routing headers that the payload did not alter.
            if (Objects.equals(originalHeaderValue, candidateHeaderValue)) continue;
            if (candidateHeaderValue == null) continue;

            // Target-specific bypass testing must continue to point at the
            // original protected resource. Dictionary swaps violate that
            // invariant and are therefore skipped rather than scored.
            if (!sameSemanticTarget(originalTarget, candidateHeaderValue)) {
                return Plan.skip(
                        "Path-swap header targets " + candidateHeaderValue
                                + " instead of protected target " + originalTarget
                );
            }

            // Neutralize only the mutation. If the captured baseline already
            // contained this routing header, restore its original value rather
            // than deleting legitimate request context.
            HttpRequest neutralControl = originalHeaderValue == null
                    ? payload.request.withRemovedHeader(header)
                    : payload.request.withHeader(header, originalHeaderValue);

            return Plan.control(
                    neutralControl,
                    originalHeaderValue == null
                            ? "Same visible path with " + header + " removed"
                            : "Same visible path with original " + header + " restored"
            );
        }

        return Plan.skip("Path-swapping payload did not change a supported routing header");
    }

    private static Plan planRoutingSurfaceControl(HttpRequestResponse baseline,
                                                  PayloadGenerator.Payload payload) {
        for (String header : ROUTING_HEADERS) {
            String originalHeaderValue = baseline.request().headerValue(header);
            String candidateHeaderValue = payload.request.headerValue(header);

            if (Objects.equals(originalHeaderValue, candidateHeaderValue)) continue;
            if (candidateHeaderValue == null || candidateHeaderValue.isBlank()) continue;

            String controlPath = routingControlPath(
                    baseline.request().path(),
                    header,
                    candidateHeaderValue
            );

            // Keep the exact routing mutation, method, headers, cookies, and
            // authentication context. Change only the resource path so a default
            // virtual host/catch-all response can be measured directly.
            HttpRequest neutralControl = payload.request.withPath(controlPath);
            return Plan.control(
                    neutralControl,
                    "Same " + canonicalHeaderName(header)
                            + " routing mutation on synthetic non-target path " + controlPath
            );
        }

        return Plan.none();
    }

    static boolean sameSemanticTarget(String originalTarget, String headerTarget) {
        if (originalTarget == null || headerTarget == null) return false;
        return originalTarget.trim().equals(headerTarget.trim());
    }

    static boolean isRoutingHeader(String headerName) {
        if (headerName == null) return false;
        return ROUTING_HEADERS.contains(headerName.trim().toLowerCase(Locale.ROOT));
    }

    static String routingControlPath(String originalTarget, String headerName, String headerValue) {
        String seed = nullToEmpty(originalTarget) + "|"
                + nullToEmpty(headerName).toLowerCase(Locale.ROOT) + "|"
                + nullToEmpty(headerValue).toLowerCase(Locale.ROOT);
        String suffix = Integer.toUnsignedString(seed.hashCode(), 16);
        String controlPath = "/__403_buster_control_" + suffix;

        // Avoid the pathological case where the protected target itself happens
        // to equal the deterministic synthetic control path.
        if (sameSemanticTarget(originalTarget, controlPath)) {
            controlPath += "_neutral";
        }
        return controlPath;
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value.trim();
    }

    private static String canonicalHeaderName(String lowerCaseHeader) {
        if ("host".equals(lowerCaseHeader)) return "Host";
        StringBuilder out = new StringBuilder();
        boolean capitalize = true;
        for (char c : lowerCaseHeader.toCharArray()) {
            if (c == '-') {
                out.append(c);
                capitalize = true;
            } else {
                out.append(capitalize ? Character.toUpperCase(c) : c);
                capitalize = false;
            }
        }
        return out.toString();
    }

    record Plan(Action action, HttpRequest controlRequest, String rationale) {
        static Plan none() {
            return new Plan(Action.NONE, null, "No paired control required");
        }

        static Plan control(HttpRequest controlRequest, String rationale) {
            return new Plan(Action.PAIRED_CONTROL, controlRequest, rationale);
        }

        static Plan skip(String rationale) {
            return new Plan(Action.SKIP, null, rationale);
        }

        boolean requiresControl() {
            return action == Action.PAIRED_CONTROL;
        }

        boolean shouldSkip() {
            return action == Action.SKIP;
        }
    }

    enum Action {
        NONE,
        PAIRED_CONTROL,
        SKIP
    }
}
