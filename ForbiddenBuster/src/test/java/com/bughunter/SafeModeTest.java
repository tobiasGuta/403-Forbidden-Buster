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
        assertFalse(RequestSafetyPolicy.isSafeAutomaticMethod("PROPFIND"));
        assertFalse(RequestSafetyPolicy.isSafeAutomaticMethod(null));
    }

    @Test
    void safeModeKeepsHeaderOnlyCoverageButStillGatesMethodTampering() {
        ActiveMethodsRegistry.configure(false, "GET");
        AttackConfig config = config(true, true, true);

        assertTrue(config.isSafeMode());
        assertFalse(config.isActiveMethodsEnabled());
        assertEquals("GET", config.getTargetMethod());

        assertTrue(config.isIpSpoofing());
        assertTrue(config.isPathSwapping());
        assertTrue(config.isHopByHop());
        assertTrue(config.isPathObfuscation());
        assertTrue(config.isProtocolDowngrade());
        assertTrue(config.isSuffixAttacks());
        assertTrue(config.isCaseSwitch());
        assertTrue(config.isUnicodeNormalization());
        assertTrue(config.isBackslashBypass());
        assertTrue(config.isHeaderInjection());
        assertFalse(config.isMethodTampering());
        assertTrue(config.validate().isEmpty());
    }

    @Test
    void safeModeQueueGateAllowsHeaderOnlyMethodsButRejectsActiveMethods() {
        ActiveMethodsRegistry.configure(false, "GET");

        assertTrue(RequestSafetyPolicy.isAllowedByCurrentMode("GET"));
        assertTrue(RequestSafetyPolicy.isAllowedByCurrentMode("HEAD"));
        assertTrue(RequestSafetyPolicy.isAllowedByCurrentMode("OPTIONS"));

        assertFalse(RequestSafetyPolicy.isAllowedByCurrentMode("POST"));
        assertFalse(RequestSafetyPolicy.isAllowedByCurrentMode("PUT"));
        assertFalse(RequestSafetyPolicy.isAllowedByCurrentMode("PATCH"));
        assertFalse(RequestSafetyPolicy.isAllowedByCurrentMode("DELETE"));
        assertFalse(RequestSafetyPolicy.isAllowedByCurrentMode("TRACE"));
        assertFalse(RequestSafetyPolicy.isAllowedByCurrentMode("CONNECT"));
    }

    @Test
    void headerInjectionCanBeTheOnlyEnabledSafeFamily() {
        ActiveMethodsRegistry.configure(false, "GET");
        AttackConfig config = new AttackConfig(
                false, false, false, false,
                false, false, false,
                false, false,
                false, false, false,
                true,
                50, 5,
                "127.0.0.1", "/admin"
        );

        assertTrue(config.isHeaderInjection());
        assertFalse(config.isMethodTampering());
        assertTrue(config.validate().isEmpty());
    }

    @Test
    void activeMethodsExplicitlyUnlockMethodAndHeaderCategories() {
        ActiveMethodsRegistry.configure(true, "POST");
        AttackConfig config = config(true, true, true);

        assertFalse(config.isSafeMode());
        assertTrue(config.isActiveMethodsEnabled());
        assertEquals("POST", config.getTargetMethod());
        assertTrue(config.isMethodTampering());
        assertTrue(config.isHeaderInjection());
        assertTrue(config.isIpSpoofing());
        assertTrue(RequestSafetyPolicy.isAllowedByCurrentMode("POST"));
        assertTrue(RequestSafetyPolicy.isAllowedByCurrentMode("DELETE"));
        assertTrue(config.validate().isEmpty());
    }

    @Test
    void safeModeRefusesNonAllowlistedTargetMethodBeforePayloadGeneration() {
        ActiveMethodsRegistry.configure(false, "POST");
        AttackConfig config = config(true, true, true);

        assertFalse(config.isIpSpoofing());
        assertFalse(config.isPathSwapping());
        assertFalse(config.isHopByHop());
        assertFalse(config.isPathObfuscation());
        assertFalse(config.isProtocolDowngrade());
        assertFalse(config.isSuffixAttacks());
        assertFalse(config.isCaseSwitch());
        assertFalse(config.isUnicodeNormalization());
        assertFalse(config.isBackslashBypass());
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
                true,
                true,
                true,
                methodTampering,
                true,
                true,
                false,
                false,
                true,
                true,
                true,
                headerInjection,
                50,
                5,
                "127.0.0.1",
                "/admin"
        );
    }
}
