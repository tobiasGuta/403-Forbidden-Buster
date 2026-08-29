package com.bughunter;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BusterUiEvidenceTest {

    @Test
    void similarityFormattingIsHumanReadableAndClamped() {
        assertEquals("—", BusterUI.formatSimilarity(-1.0));
        assertEquals("0.0%", BusterUI.formatSimilarity(0.0));
        assertEquals("12.5%", BusterUI.formatSimilarity(0.125));
        assertEquals("100.0%", BusterUI.formatSimilarity(1.0));
        assertEquals("100.0%", BusterUI.formatSimilarity(2.0));
    }

    @Test
    void stableCandidateShowsRepeatabilityAndEvidence() {
        BypassResult result = result(
                ResponseAnalyzer.ResultType.BYPASS_CANDIDATE,
                92,
                0.14,
                true,
                200,
                0.11,
                true,
                3,
                3,
                "403 -> 200; denial markers disappeared",
                "Stable 3/3 candidate"
        );

        assertEquals("BYPASS_CANDIDATE", BusterUI.classificationLabel(result));
        assertEquals("3/3", BusterUI.repeatabilityLabel(result));

        String summary = BusterUI.buildEvidenceSummary(result);
        assertTrue(summary.contains("Confidence     : 92 / 100"));
        assertTrue(summary.contains("Baseline sim.  : 14.0%"));
        assertTrue(summary.contains("Control status : 200"));
        assertTrue(summary.contains("Control sim.   : 11.0%"));
        assertTrue(summary.contains("Repeatability  : 3/3"));
        assertTrue(summary.contains("denial markers disappeared"));
        assertTrue(summary.contains("Stable 3/3 candidate"));
        assertTrue(summary.contains("Manual validation is still required"));
    }

    @Test
    void nonReplayedActiveCandidateShowsManualValidation() {
        BypassResult result = result(
                ResponseAnalyzer.ResultType.BYPASS_CANDIDATE,
                70,
                0.25,
                false,
                -1,
                -1.0,
                false,
                0,
                1,
                "Interesting active-method response",
                "Automatic revalidation skipped for POST"
        );

        assertEquals("manual", BusterUI.repeatabilityLabel(result));
        String summary = BusterUI.buildEvidenceSummary(result);
        assertTrue(summary.contains("Control        : not required"));
        assertTrue(summary.contains("Repeatability  : manual"));
        assertTrue(summary.contains("Automatic revalidation skipped for POST"));
    }

    @Test
    void tableModelExposesEvidenceColumnsForFastTriage() {
        BusterUI.ResultTableModel model = new BusterUI.ResultTableModel();
        BypassResult result = result(
                ResponseAnalyzer.ResultType.STATUS_ANOMALY,
                40,
                0.55,
                false,
                -1,
                -1.0,
                true,
                1,
                3,
                "Unstable status change",
                "Only 1/3 consistent"
        );
        model.addResult(result);

        assertEquals(9, model.getColumnCount());
        assertEquals("Confidence", model.getColumnName(1));
        assertEquals("Classification", model.getColumnName(2));
        assertEquals("Baseline Sim", model.getColumnName(4));
        assertEquals("Control Sim", model.getColumnName(5));
        assertEquals("Repeat", model.getColumnName(6));
        assertEquals(40, model.getValueAt(0, 1));
        assertEquals("STATUS_ANOMALY", model.getValueAt(0, 2));
        assertEquals("55.0%", model.getValueAt(0, 4));
        assertEquals("—", model.getValueAt(0, 5));
        assertEquals("1/3", model.getValueAt(0, 6));
    }

    private static BypassResult result(ResponseAnalyzer.ResultType classification,
                                       int confidence,
                                       double baselineSimilarity,
                                       boolean controlCompared,
                                       int controlStatus,
                                       double controlSimilarity,
                                       boolean revalidationAttempted,
                                       int repeatabilityPasses,
                                       int repeatabilitySamples,
                                       String rationale,
                                       String revalidationRationale) {
        return new BypassResult(
                7,
                "GET",
                "https://example.test/admin",
                "X-Original-URL: /admin",
                "Path Swapping",
                200,
                512,
                null,
                classification,
                confidence,
                baselineSimilarity,
                rationale,
                null,
                controlCompared,
                controlStatus,
                controlSimilarity,
                revalidationAttempted,
                repeatabilityPasses,
                repeatabilitySamples,
                revalidationRationale
        );
    }
}
