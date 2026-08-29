package com.bughunter;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PairedControlPlannerTest {

    @Test
    void exactProtectedTargetIsPreserved() {
        assertTrue(PairedControlPlanner.sameSemanticTarget(
                "/admin?view=users",
                "/admin?view=users"
        ));
    }

    @Test
    void harmlessSurroundingWhitespaceDoesNotChangeTargetIdentity() {
        assertTrue(PairedControlPlanner.sameSemanticTarget(
                "/admin",
                "  /admin  "
        ));
    }

    @Test
    void dictionaryTargetCannotMasqueradeAsProtectedTarget() {
        assertFalse(PairedControlPlanner.sameSemanticTarget(
                "/secret-company-admin",
                "/login"
        ));
    }

    @Test
    void queryDifferenceIsARealSemanticTargetDifference() {
        assertFalse(PairedControlPlanner.sameSemanticTarget(
                "/admin?view=users",
                "/admin?view=settings"
        ));
    }

    @Test
    void nullTargetsAreRejected() {
        assertFalse(PairedControlPlanner.sameSemanticTarget("/admin", null));
        assertFalse(PairedControlPlanner.sameSemanticTarget(null, "/admin"));
    }
}
