package com.bughunter;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Objects;

/**
 * Plans neutral paired controls for mutations that intentionally change the
 * visible request target. The control keeps the same visible request while
 * removing only the bypass signal, which lets v8 distinguish an ignored
 * mutation from a response genuinely caused by the bypass technique.
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
