package com.bughunter;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ResponseAnalyzerTest {

    @Test
    void strongGetTransitionBecomesBypassCandidateNotConfirmedBypass() {
        String denied = "<html><title>Forbidden</title><body>Access denied. Request id 123456</body></html>";
        String allowed = "{\"user\":\"admin\",\"role\":\"administrator\",\"settings\":[\"billing\",\"users\"]}";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");

        ResponseAnalyzer.Analysis analysis = analyzer.analyze(
                "GET", (short) 200, allowed.length(), allowed, false, false);

        assertEquals(ResponseAnalyzer.ResultType.BYPASS_CANDIDATE, analysis.type());
        assertTrue(analysis.confidence() >= 60);
        assertTrue(analysis.shouldLog());
    }

    @Test
    void twoHundredWithSameDenialBodyIsOnlyStatusAnomaly() {
        String denied = "Forbidden - access denied";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");

        ResponseAnalyzer.Analysis analysis = analyzer.analyze(
                "GET", (short) 200, denied.length(), denied, false, false);

        assertEquals(ResponseAnalyzer.ResultType.STATUS_ANOMALY, analysis.type());
        assertTrue(analysis.confidence() < 60);
    }

    @Test
    void options204IsMethodBehaviorNotBypassCandidate() {
        String denied = "Forbidden - access denied";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");

        ResponseAnalyzer.Analysis analysis = analyzer.analyze(
                "OPTIONS", (short) 204, 0, "", false, false);

        assertEquals(ResponseAnalyzer.ResultType.METHOD_BEHAVIOR, analysis.type());
        assertTrue(analysis.confidence() < 60);
        assertTrue(analysis.shouldLog());
    }

    @Test
    void sameStatusWithDifferentBodyIsBodyAnomaly() {
        String denied = "Forbidden - access denied";
        String changed = "Different backend response with another message";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");

        ResponseAnalyzer.Analysis analysis = analyzer.analyze(
                "GET", (short) 403, denied.length(), changed, false, false);

        assertEquals(ResponseAnalyzer.ResultType.BODY_ANOMALY, analysis.type());
    }

    @Test
    void percentageLengthDifferenceUsesSameRuleForClassification() {
        String baseline = "same semantic body";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, 200, baseline, "GET");

        ResponseAnalyzer.Analysis analysis = analyzer.analyze(
                "GET", (short) 403, 230, baseline, false, false);

        assertEquals(ResponseAnalyzer.ResultType.LENGTH_ANOMALY, analysis.type());
        assertTrue(analysis.significantLengthDifference());
    }

    @Test
    void dynamicIdentifiersAreNormalizedBeforeSimilarityComparison() {
        String first = "Forbidden request 123456 id 550e8400-e29b-41d4-a716-446655440000";
        String second = "Forbidden request 987654 id 123e4567-e89b-42d3-a456-556642440000";

        double similarity = ResponseAnalyzer.bodySimilarity(first, second);

        assertEquals(1.0, similarity, 0.0001);
    }

    @Test
    void hide404SuppressesResultCompletely() {
        String denied = "Forbidden";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");

        ResponseAnalyzer.Analysis analysis = analyzer.analyze(
                "GET", (short) 404, 20, "Not found", true, false);

        assertEquals(ResponseAnalyzer.ResultType.NORMAL, analysis.type());
        assertFalse(analysis.shouldLog());
    }

    @Test
    void redirectRemainsCandidateForManualInspectionOnly() {
        String denied = "Forbidden - access denied";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");

        ResponseAnalyzer.Analysis analysis = analyzer.analyze(
                "GET", (short) 302, 0, "", false, false);

        assertEquals(ResponseAnalyzer.ResultType.REDIRECT, analysis.type());
        assertTrue(analysis.interesting());
        assertTrue(analysis.confidence() < 60);
    }
}
