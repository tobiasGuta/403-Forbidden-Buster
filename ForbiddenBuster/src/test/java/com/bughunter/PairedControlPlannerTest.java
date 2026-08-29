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
    void dictionaryTargetCannotMasqueradeAsProtectedTarget() {
        assertFalse(PairedControlPlanner.sameSemanticTarget(
                "/secret-company-admin",
                "/login"
        ));
    }

    @Test
    void nullTargetsAreRejected() {
        assertFalse(PairedControlPlanner.sameSemanticTarget("/admin", null));
        assertFalse(PairedControlPlanner.sameSemanticTarget(null, "/admin"));
    }
}
