package com.bughunter;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CandidateRevalidationTest {

    @Test
    void threeOfThreeStableCandidateKeepsClassificationAndConfidence() {
        String denied = "Forbidden access denied";
        String allowed = "admin dashboard billing users settings";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");

        ResponseAnalyzer.Analysis initial = analyzer.analyze(
                "GET", (short) 200, allowed.length(), allowed, false, false);
        assertEquals(ResponseAnalyzer.ResultType.BYPASS_CANDIDATE, initial.type());

        ResponseAnalyzer.Analysis replayAnalysis = analyzer.analyze(
                "GET", (short) 200, allowed.length(), allowed, false, false);

        CandidateRevalidation.Summary summary = CandidateRevalidation.summarize(
                (short) 200,
                allowed,
                initial,
                List.of(
                        new CandidateRevalidation.Observation((short) 200, allowed, replayAnalysis),
                        new CandidateRevalidation.Observation((short) 200, allowed, replayAnalysis)
                ),
                2
        );

        assertEquals(ResponseAnalyzer.ResultType.BYPASS_CANDIDATE, summary.classification());
        assertTrue(summary.attempted());
        assertEquals(3, summary.consistentPasses());
        assertEquals(3, summary.totalSamples());
        assertTrue(summary.confidence() >= initial.confidence());
        assertTrue(summary.confidence() <= 100);
        assertTrue(summary.rationale().contains("3/3"));
    }

    @Test
    void unstableReplayDowngradesCandidate() {
        String denied = "Forbidden access denied";
        String allowed = "admin dashboard billing users settings";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");

        ResponseAnalyzer.Analysis initial = analyzer.analyze(
                "GET", (short) 200, allowed.length(), allowed, false, false);
        ResponseAnalyzer.Analysis deniedReplay = analyzer.analyze(
                "GET", (short) 403, denied.length(), denied, false, false);

        CandidateRevalidation.Summary summary = CandidateRevalidation.summarize(
                (short) 200,
                allowed,
                initial,
                List.of(
                        new CandidateRevalidation.Observation((short) 200, allowed, initial),
                        new CandidateRevalidation.Observation((short) 403, denied, deniedReplay)
                ),
                2
        );

        assertEquals(ResponseAnalyzer.ResultType.STATUS_ANOMALY, summary.classification());
        assertEquals(2, summary.consistentPasses());
        assertEquals(3, summary.totalSamples());
        assertTrue(summary.confidence() <= 55);
        assertTrue(summary.rationale().contains("2/3"));
    }

    @Test
    void sameStatusButDifferentBodyDoesNotCountAsRepeatable() {
        String denied = "Forbidden access denied";
        String allowed = "admin dashboard billing users settings";
        String unrelated = "public homepage news contact about products";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");

        ResponseAnalyzer.Analysis initial = analyzer.analyze(
                "GET", (short) 200, allowed.length(), allowed, false, false);
        ResponseAnalyzer.Analysis replayAnalysis = analyzer.analyze(
                "GET", (short) 200, unrelated.length(), unrelated, false, false);

        CandidateRevalidation.Observation observation =
                new CandidateRevalidation.Observation((short) 200, unrelated, replayAnalysis);

        assertFalse(CandidateRevalidation.isConsistent((short) 200, allowed, observation));
    }

    @Test
    void pairedControlMatchOnReplayBreaksRepeatability() {
        String denied = "Forbidden access denied";
        String homepage = "public homepage news contact about products";
        String admin = "admin dashboard billing users settings";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");

        ResponseAnalyzer.Analysis initial = analyzer.analyzeWithControl(
                "GET",
                (short) 200, admin.length(), admin,
                (short) 200, homepage.length(), homepage,
                false, false
        );
        assertEquals(ResponseAnalyzer.ResultType.BYPASS_CANDIDATE, initial.type());

        ResponseAnalyzer.Analysis replay = analyzer.analyzeWithControl(
                "GET",
                (short) 200, homepage.length(), homepage,
                (short) 200, homepage.length(), homepage,
                false, false
        );
        assertEquals(ResponseAnalyzer.ResultType.CONTROL_MATCH, replay.type());

        CandidateRevalidation.Summary summary = CandidateRevalidation.summarize(
                (short) 200,
                admin,
                initial,
                List.of(
                        new CandidateRevalidation.Observation((short) 200, homepage, replay),
                        new CandidateRevalidation.Observation((short) 200, homepage, replay)
                ),
                2
        );

        assertEquals(ResponseAnalyzer.ResultType.STATUS_ANOMALY, summary.classification());
        assertEquals(1, summary.consistentPasses());
        assertTrue(summary.confidence() <= 40);
    }

    @Test
    void nonCandidateIsNotRevalidated() {
        String denied = "Forbidden access denied";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");
        ResponseAnalyzer.Analysis anomaly = analyzer.analyze(
                "GET", (short) 200, denied.length(), denied, false, false);

        CandidateRevalidation.Summary summary = CandidateRevalidation.summarize(
                (short) 200, denied, anomaly, List.of(), 2);

        assertFalse(summary.attempted());
        assertEquals(anomaly.type(), summary.classification());
        assertEquals(anomaly.confidence(), summary.confidence());
    }

    @Test
    void incompleteReplayCannotRemainHighConfidenceCandidate() {
        String denied = "Forbidden access denied";
        String allowed = "admin dashboard billing users settings";
        ResponseAnalyzer analyzer = new ResponseAnalyzer((short) 403, denied.length(), denied, "GET");
        ResponseAnalyzer.Analysis initial = analyzer.analyze(
                "GET", (short) 200, allowed.length(), allowed, false, false);

        CandidateRevalidation.Summary summary = CandidateRevalidation.summarize(
                (short) 200,
                allowed,
                initial,
                List.of(new CandidateRevalidation.Observation((short) 200, allowed, initial)),
                2
        );

        assertEquals(ResponseAnalyzer.ResultType.STATUS_ANOMALY, summary.classification());
        assertTrue(summary.confidence() <= 50);
        assertTrue(summary.rationale().contains("before all planned replays completed"));
    }
}
