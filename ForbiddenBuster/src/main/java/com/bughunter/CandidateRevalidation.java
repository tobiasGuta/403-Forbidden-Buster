package com.bughunter;

import java.util.List;

/**
 * Pure repeatability scoring for v8 high-signal candidates.
 *
 * A replay only counts as consistent when it is still classified as a
 * BYPASS_CANDIDATE, returns the same status as the original candidate, and its
 * normalized body remains similar to the original candidate response.
 */
final class CandidateRevalidation {

    static final double MIN_CANDIDATE_BODY_SIMILARITY = 0.80;

    private CandidateRevalidation() {}

    record Observation(short status, String body, ResponseAnalyzer.Analysis analysis) {}

    record Summary(
            ResponseAnalyzer.ResultType classification,
            int confidence,
            boolean attempted,
            int consistentPasses,
            int totalSamples,
            String rationale
    ) {
        static Summary skipped(ResponseAnalyzer.ResultType classification,
                               int confidence,
                               String rationale) {
            int initialPasses = classification == ResponseAnalyzer.ResultType.BYPASS_CANDIDATE ? 1 : 0;
            return new Summary(classification, confidence, false, initialPasses, 1, rationale);
        }
    }

    static Summary summarize(short initialStatus,
                             String initialBody,
                             ResponseAnalyzer.Analysis initialAnalysis,
                             List<Observation> observations,
                             int expectedAdditionalAttempts) {
        if (initialAnalysis.type() != ResponseAnalyzer.ResultType.BYPASS_CANDIDATE) {
            return Summary.skipped(
                    initialAnalysis.type(),
                    initialAnalysis.confidence(),
                    "Revalidation not required for " + initialAnalysis.type()
            );
        }

        int consistentAdditional = 0;
        for (Observation observation : observations) {
            if (isConsistent(initialStatus, initialBody, observation)) {
                consistentAdditional++;
            }
        }

        int totalSamples = 1 + observations.size();
        int consistentPasses = 1 + consistentAdditional;
        boolean completedAll = observations.size() == expectedAdditionalAttempts;
        boolean allConsistent = completedAll && consistentAdditional == expectedAdditionalAttempts;

        if (allConsistent) {
            int confidence = clamp(initialAnalysis.confidence() + 15);
            return new Summary(
                    ResponseAnalyzer.ResultType.BYPASS_CANDIDATE,
                    confidence,
                    true,
                    consistentPasses,
                    totalSamples,
                    "Repeatability " + consistentPasses + "/" + totalSamples
                            + "; candidate remained stable across all safe replays"
            );
        }

        int confidencePenalty = consistentAdditional == 0 ? 30 : 15;
        int confidenceCap;
        if (!completedAll) {
            confidenceCap = 50;
        } else if (consistentAdditional == 0) {
            confidenceCap = 40;
        } else {
            confidenceCap = 55;
        }
        int confidence = Math.min(confidenceCap,
                clamp(initialAnalysis.confidence() - confidencePenalty));

        String completion = completedAll
                ? "candidate did not remain stable across every replay"
                : "revalidation ended before all planned replays completed";

        return new Summary(
                ResponseAnalyzer.ResultType.STATUS_ANOMALY,
                confidence,
                true,
                consistentPasses,
                totalSamples,
                "Repeatability " + consistentPasses + "/" + totalSamples + "; " + completion
        );
    }

    static boolean isConsistent(short initialStatus,
                                String initialBody,
                                Observation observation) {
        if (observation == null || observation.analysis() == null) return false;
        if (observation.analysis().type() != ResponseAnalyzer.ResultType.BYPASS_CANDIDATE) return false;
        if (observation.status() != initialStatus) return false;

        double similarity = ResponseAnalyzer.bodySimilarity(initialBody, observation.body());
        return similarity >= MIN_CANDIDATE_BODY_SIMILARITY;
    }

    private static int clamp(int value) {
        return Math.max(0, Math.min(100, value));
    }
}
