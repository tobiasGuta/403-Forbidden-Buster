package com.bughunter;

import burp.api.montoya.http.message.responses.analysis.AttributeType;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class MontoyaResponseEvidenceTest {

    @Test
    void semanticSummaryIsStableAndReadable() {
        MontoyaResponseEvidence.Evidence evidence = new MontoyaResponseEvidence.Evidence(
                true,
                Set.of(AttributeType.VISIBLE_TEXT, AttributeType.LOCATION, AttributeType.PAGE_TITLE),
                Set.of("forbidden", "access denied"),
                Set.of(AttributeType.LOCATION, AttributeType.CONTENT_TYPE),
                Set.of("unauthorized"),
                "/admin/dashboard",
                "/login",
                ""
        );

        String summary = evidence.summary();

        assertTrue(summary.contains("stable-baseline variants=LOCATION|PAGE_TITLE|VISIBLE_TEXT"));
        assertTrue(summary.contains("denial-keyword count variants=access denied|forbidden"));
        assertTrue(summary.contains("candidate/control variants=CONTENT_TYPE|LOCATION"));
        assertTrue(summary.contains("candidate/control denial-keyword variants=unauthorized"));
        assertTrue(evidence.locationVariesFromStableBaseline());
        assertTrue(evidence.locationVariesFromControl());
    }

    @Test
    void emptySemanticEvidenceDoesNotInventDifferences() {
        MontoyaResponseEvidence.Evidence evidence = new MontoyaResponseEvidence.Evidence(
                true, Set.of(), Set.of(), Set.of(), Set.of(), "", "", ""
        );

        assertEquals("No selected Montoya semantic variations", evidence.summary());
        assertFalse(evidence.locationVariesFromStableBaseline());
        assertFalse(evidence.locationVariesFromControl());
    }

    @Test
    void unavailableEvidencePreservesFailureReasonWithoutPromotingAnything() {
        MontoyaResponseEvidence.Evidence evidence = MontoyaResponseEvidence.Evidence.unavailable(
                "Montoya semantic analysis unavailable: test failure"
        );

        assertFalse(evidence.available());
        assertEquals("Montoya semantic analysis unavailable: test failure", evidence.summary());
        assertTrue(evidence.baselineStableVariants().isEmpty());
        assertTrue(evidence.denialKeywordVariants().isEmpty());
    }

    @Test
    void attributeFormattingIsDeterministic() {
        assertEquals(
                "CONTENT_TYPE|LOCATION|VISIBLE_TEXT",
                MontoyaResponseEvidence.formatAttributes(
                        Set.of(AttributeType.VISIBLE_TEXT, AttributeType.CONTENT_TYPE, AttributeType.LOCATION)
                )
        );
        assertEquals("none", MontoyaResponseEvidence.formatAttributes(Set.of()));
    }
}
