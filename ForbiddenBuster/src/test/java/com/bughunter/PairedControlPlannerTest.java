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

    @Test
    void hostLikeRoutingHeadersAreExplicitlyRecognized() {
        assertTrue(PairedControlPlanner.isRoutingHeader("Host"));
        assertTrue(PairedControlPlanner.isRoutingHeader("x-forwarded-host"));
        assertTrue(PairedControlPlanner.isRoutingHeader(" X-Host "));
        assertTrue(PairedControlPlanner.isRoutingHeader("X-Original-Host"));
        assertTrue(PairedControlPlanner.isRoutingHeader("X-Backend-Host"));
        assertTrue(PairedControlPlanner.isRoutingHeader("X-Forwarded-Server"));

        assertFalse(PairedControlPlanner.isRoutingHeader("X-Forwarded-For"));
        assertFalse(PairedControlPlanner.isRoutingHeader("X-Forwarded-Proto"));
        assertFalse(PairedControlPlanner.isRoutingHeader("Authorization"));
        assertFalse(PairedControlPlanner.isRoutingHeader(null));
    }

    @Test
    void routingControlPathIsDeterministicAndNeverTheProtectedTarget() {
        String first = PairedControlPlanner.routingControlPath(
                "/admin?view=users",
                "Host",
                "localhost"
        );
        String second = PairedControlPlanner.routingControlPath(
                "/admin?view=users",
                "host",
                "LOCALHOST"
        );

        assertEquals(first, second);
        assertTrue(first.startsWith("/__403_buster_control_"));
        assertNotEquals("/admin?view=users", first);
    }

    @Test
    void routingControlPathChangesWhenRoutingSurfaceChanges() {
        String localhost = PairedControlPlanner.routingControlPath(
                "/admin",
                "Host",
                "localhost"
        );
        String loopback = PairedControlPlanner.routingControlPath(
                "/admin",
                "Host",
                "127.0.0.1"
        );
        String forwardedHost = PairedControlPlanner.routingControlPath(
                "/admin",
                "X-Forwarded-Host",
                "localhost"
        );

        assertNotEquals(localhost, loopback);
        assertNotEquals(localhost, forwardedHost);
    }
}
