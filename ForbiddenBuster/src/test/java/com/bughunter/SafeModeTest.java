package com.bughunter;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SafeModeTest {

    @AfterEach
    void resetRegistry() {
        ActiveMethodsRegistry.reset();
    }

    @Test
    void safeAutomaticMethodsAreExplicitlyAllowlisted() {
        assertTrue(RequestSafetyPolicy.isSafeAutomaticMethod("GET"));
        assertTrue(RequestSafetyPolicy.isSafeAutomaticMethod("head"));
        assertTrue(RequestSafetyPolicy.isSafeAutomaticMethod(" OPTIONS "));

        assertFalse(RequestSafetyPolicy.isSafeAutomaticMethod("POST"));
        assertFalse(RequestSafetyPolicy.isSafeAutomaticMethod("PUT"));
        assertFalse(RequestSafetyPolicy.isSafeAutomaticMethod("PATCH"));
        assertFalse(RequestSafetyPolicy.isSafeAutomaticMethod("DELETE"));
        assertFalse(RequestSafetyPolicy.isSafeAutomaticMethod("TRACE"));
        assertFalse(RequestSafetyPolicy.isSafeAutomaticMethod("CONNECT"));
        assertFalse(RequestSafetyPolicy.isSafeAutomaticMethod(null));
    }

    @Test
    void safeModeKeepsOrdinaryGetFamiliesButGatesMixedActiveCategories() {
        ActiveMethodsRegistry.configure(false, "GET");
        AttackConfig config = config(true, true, true);

        assertTrue(config.isSafeMode());
        assertFalse(config.isActiveMethodsEnabled());
        assertEquals("GET", config.getTargetMethod());

        assertTrue(config.isIpSpoofing());
        assertTrue(config.isPathSwapping());
        assertFalse(config.isMethodTampering());
        assertFalse(config.isHeaderInjection());
        assertTrue(config.validate().isEmpty());
    }

    @Test
    void activeMethodsExplicitlyUnlockMethodAndMixedHeaderCategories() {
        ActiveMethodsRegistry.configure(true, "POST");
        AttackConfig config = config(true, true, true);

        assertFalse(config.isSafeMode());
        assertTrue(config.isActiveMethodsEnabled());
        assertEquals("POST", config.getTargetMethod());
        assertTrue(config.isMethodTampering());
        assertTrue(config.isHeaderInjection());
        assertTrue(config.isIpSpoofing());
        assertTrue(config.validate().isEmpty());
    }

    @Test
    void safeModeRefusesNonAllowlistedTargetMethodBeforePayloadGeneration() {
        ActiveMethodsRegistry.configure(false, "POST");
        AttackConfig config = config(true, true, true);

        assertFalse(config.isIpSpoofing());
        assertFalse(config.isPathSwapping());
        assertFalse(config.isMethodTampering());
        assertFalse(config.isHeaderInjection());

        List<String> errors = config.validate();
        assertTrue(errors.stream().anyMatch(e -> e.contains("Safe Mode will not transmit a POST target")));
    }

    @Test
    void activeModeIsNonStickyAfterRegistryReset() {
        ActiveMethodsRegistry.configure(true, "DELETE");
        assertTrue(ActiveMethodsRegistry.isActiveMethodsEnabled());

        ActiveMethodsRegistry.reset();
        assertFalse(ActiveMethodsRegistry.isActiveMethodsEnabled());
        assertEquals("GET", ActiveMethodsRegistry.targetMethod());
    }

    private static AttackConfig config(boolean ipSpoofing,
                                       boolean methodTampering,
                                       boolean headerInjection) {
        return new AttackConfig(
                ipSpoofing,
                true,   // path swapping
                true,   // hop-by-hop
                true,   // path obfuscation
                methodTampering,
                true,   // protocol variants
                true,   // suffix attacks
                false,
                false,
                true,   // case switching
                true,   // unicode normalization
                true,   // backslash
                headerInjection,
                50,
                5,
                "127.0.0.1",
                "/admin"
        );
    }
}
