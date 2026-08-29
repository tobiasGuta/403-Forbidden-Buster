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
    void pairedControlMatchSuppressesRootPageFalsePositive() {
        String denied = "Forbidden - access denied";
        String homepageControl = "Welcome home products pricing documentation";
        String candidate = "Welcome home products pricing documentation";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");

        ResponseAnalyzer.Analysis analysis = analyzer.analyzeWithControl(
                "GET",
                (short) 200, candidate.length(), candidate,
                (short) 200, homepageControl.length(), homepageControl,
                false, false
        );

        assertEquals(ResponseAnalyzer.ResultType.CONTROL_MATCH, analysis.type());
        assertEquals(0, analysis.confidence());
        assertFalse(analysis.shouldLog());
        assertTrue(analysis.controlCompared());
        assertEquals(1.0, analysis.controlSimilarity(), 0.0001);
    }

    @Test
    void genericDefaultVhostResponseIsSuppressedAsControlMatch() {
        String denied = "Forbidden - access denied";
        String genericVhost = "Default virtual host. Nothing configured here.";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");

        ResponseAnalyzer.Analysis analysis = analyzer.analyzeWithControl(
                "GET",
                (short) 200, genericVhost.length(), genericVhost,
                (short) 200, genericVhost.length(), genericVhost,
                false, false
        );

        assertEquals(ResponseAnalyzer.ResultType.CONTROL_MATCH, analysis.type());
        assertEquals(0, analysis.confidence());
        assertFalse(analysis.shouldLog());
        assertTrue(analysis.rationale().contains("routing-surface behavior"));
        assertTrue(analysis.rationale().contains("protected-resource access"));
    }

    @Test
    void pairedControlDifferenceStrengthensRealBypassCandidate() {
        String denied = "Forbidden - access denied";
        String homepageControl = "Welcome home products pricing documentation";
        String adminCandidate = "Admin dashboard users billing secrets configuration";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");

        ResponseAnalyzer.Analysis analysis = analyzer.analyzeWithControl(
                "GET",
                (short) 200, adminCandidate.length(), adminCandidate,
                (short) 200, homepageControl.length(), homepageControl,
                false, false
        );

        assertEquals(ResponseAnalyzer.ResultType.BYPASS_CANDIDATE, analysis.type());
        assertTrue(analysis.confidence() >= 60);
        assertTrue(analysis.shouldLog());
        assertTrue(analysis.controlCompared());
        assertTrue(analysis.controlSimilarity() < 0.35);
    }

    @Test
    void pairedControlWithDifferentStatusAddsDifferentialEvidence() {
        String denied = "Forbidden - access denied";
        String notFound = "Not found";
        String adminCandidate = "Admin dashboard users billing configuration";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");

        ResponseAnalyzer.Analysis analysis = analyzer.analyzeWithControl(
                "GET",
                (short) 200, adminCandidate.length(), adminCandidate,
                (short) 404, notFound.length(), notFound,
                false, false
        );

        assertEquals(ResponseAnalyzer.ResultType.BYPASS_CANDIDATE, analysis.type());
        assertTrue(analysis.confidence() >= 70);
        assertEquals(404, analysis.controlStatus());
    }

    @Test
    void redirectIsNotSuppressedFromEmptyBodyControlAlone() {
        String denied = "Forbidden - access denied";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");

        ResponseAnalyzer.Analysis analysis = analyzer.analyzeWithControl(
                "GET",
                (short) 302, 0, "",
                (short) 302, 0, "",
                false, false
        );

        assertEquals(ResponseAnalyzer.ResultType.REDIRECT, analysis.type());
        assertTrue(analysis.shouldLog());
        assertTrue(analysis.controlCompared());
    }

    @Test
    void identicalRedirectLocationMatchesPairedControlAndIsSuppressed() {
        String denied = "Forbidden - access denied";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");

        ResponseAnalyzer.Analysis analysis = analyzer.analyzeWithControl(
                "GET",
                (short) 302, 0, "", "https://example.test/login#continue",
                (short) 302, 0, "", "https://EXAMPLE.test:443/login",
                false, false
        );

        assertEquals(ResponseAnalyzer.ResultType.CONTROL_MATCH, analysis.type());
        assertEquals(0, analysis.confidence());
        assertFalse(analysis.shouldLog());
        assertTrue(analysis.rationale().contains("Redirect destination matches paired control"));
    }

    @Test
    void loginRedirectIsKeptLowConfidence() {
        String denied = "Forbidden - access denied";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");

        ResponseAnalyzer.Analysis analysis = analyzer.analyze(
                "GET", (short) 302, 0, "", "/login?next=%2Fadmin", false, false);

        assertEquals(ResponseAnalyzer.ResultType.REDIRECT, analysis.type());
        assertTrue(analysis.confidence() <= 15);
        assertTrue(analysis.rationale().contains("authentication/denial-like"));
    }

    @Test
    void redirectThatDiffersFromLoginControlRemainsManualInspectionSignal() {
        String denied = "Forbidden - access denied";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");

        ResponseAnalyzer.Analysis analysis = analyzer.analyzeWithControl(
                "GET",
                (short) 302, 0, "", "/admin/dashboard",
                (short) 302, 0, "", "/login",
                false, false
        );

        assertEquals(ResponseAnalyzer.ResultType.REDIRECT, analysis.type());
        assertTrue(analysis.shouldLog());
        assertTrue(analysis.confidence() > 15);
        assertTrue(analysis.rationale().contains("control Location=/login"));
    }

    @Test
    void redirectLocationNormalizationDropsFragmentsAndDefaultPorts() {
        assertTrue(ResponseAnalyzer.locationsEquivalent(
                "https://EXAMPLE.test:443/login#step-two",
                "https://example.test/login"
        ));
        assertFalse(ResponseAnalyzer.locationsEquivalent(
                "/admin?view=users",
                "/admin?view=settings"
        ));
        assertEquals("/login?next=%2Fadmin", ResponseAnalyzer.normalizeLocation(" /login?next=%2Fadmin#frag "));
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
    void secondaryBaselineSampleAbsorbsLegitimateDynamicVariance() {
        String first = "Forbidden access denied edge template alpha";
        String second = "Forbidden access denied edge template beta with extra dynamic content";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, first.length(), first, "GET");

        assertTrue(analyzer.addBaselineSample((short) 403, second.length(), second));
        assertEquals(2, analyzer.getBaselineSampleCount());

        ResponseAnalyzer.Analysis analysis = analyzer.analyze(
                "GET", (short) 403, second.length(), second, false, false);

        assertEquals(ResponseAnalyzer.ResultType.NORMAL, analysis.type());
        assertFalse(analysis.shouldLog());
        assertEquals(1.0, analysis.bodySimilarity(), 0.0001);
    }

    @Test
    void changedAuthorizationStatusCannotPolluteBaselineProfile() {
        String denied = "Forbidden access denied";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");

        assertFalse(analyzer.addBaselineSample((short) 200, 100, "Admin dashboard"));
        assertEquals(1, analyzer.getBaselineSampleCount());
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
