package com.bughunter;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Plans neutral paired controls for mutations that intentionally change the
 * visible request target. The control keeps the same visible request while
 * removing the bypass signal, which lets v8 distinguish an ignored mutation
 * from a response that is genuinely caused by the bypass technique.
 */
final class PairedControlPlanner {

    private static final String PATH_SWAPPING = "Path Swapping";
    private static final String[] PATH_SWAP_HEADERS = {"X-Original-URL", "X-Rewrite-URL"};

    private PairedControlPlanner() {}

    static Plan plan(HttpRequestResponse baseline, PayloadGenerator.Payload payload) {
        if (!PATH_SWAPPING.equals(payload.category)) {
            return Plan.none();
        }

        String originalTarget = baseline.request().path();
        for (String header : PATH_SWAP_HEADERS) {
            String headerTarget = payload.request.headerValue(header);
            if (headerTarget == null) continue;

            // Target-specific bypass testing must continue to point at the
            // original protected resource. Dictionary swaps violate that
            // invariant and are therefore skipped rather than scored.
            if (!sameSemanticTarget(originalTarget, headerTarget)) {
                return Plan.skip(
                        "Path-swap header targets " + headerTarget
                                + " instead of protected target " + originalTarget
                );
            }

            HttpRequest neutralControl = payload.request.withRemovedHeader(header);
            return Plan.control(
                    neutralControl,
                    "Same visible path with " + header + " removed"
            );
        }

        return Plan.skip("Path-swapping payload has no supported routing header");
    }

    static boolean sameSemanticTarget(String originalTarget, String headerTarget) {
        if (originalTarget == null || headerTarget == null) return false;
        return originalTarget.trim().equals(headerTarget.trim());
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
