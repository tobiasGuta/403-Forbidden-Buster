package com.bughunter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Immutable configuration holder for an attack run. Includes input validation
 * and the v8 Safe Mode policy.
 */
public class AttackConfig {

    // Requested toggle states
    private final boolean ipSpoofing;
    private final boolean pathSwapping;
    private final boolean hopByHop;
    private final boolean pathObfuscation;
    private final boolean methodTampering;
    private final boolean protocolDowngrade;
    private final boolean suffixAttacks;
    private final boolean hide404;
    private final boolean hide403;
    private final boolean caseSwitch;
    private final boolean unicodeNormalization;
    private final boolean backslashBypass;
    private final boolean headerInjection;

    // v8 safety profile. False means Safe Mode.
    private final boolean activeMethodsEnabled;
    private final String targetMethod;

    // Scan settings
    private final int delayMs;
    private final int threadCount;

    // Custom lists
    private final List<String> userIPs;
    private final List<String> userPaths;

    /**
     * UI-compatible constructor. The per-target execution mode is deliberately
     * ephemeral and comes from the current Burp context-menu selection.
     */
    public AttackConfig(boolean ipSpoofing, boolean pathSwapping, boolean hopByHop,
                        boolean pathObfuscation, boolean methodTampering, boolean protocolDowngrade,
                        boolean suffixAttacks, boolean hide404, boolean hide403,
                        boolean caseSwitch, boolean unicodeNormalization, boolean backslashBypass,
                        boolean headerInjection,
                        int delayMs, int threadCount,
                        String ipListRaw, String pathListRaw) {
        this(ipSpoofing, pathSwapping, hopByHop, pathObfuscation, methodTampering,
                protocolDowngrade, suffixAttacks, hide404, hide403, caseSwitch,
                unicodeNormalization, backslashBypass, headerInjection,
                ActiveMethodsRegistry.isActiveMethodsEnabled(), ActiveMethodsRegistry.targetMethod(),
                delayMs, threadCount, ipListRaw, pathListRaw);
    }

    /**
     * Compatibility constructor for callers that explicitly choose the mode.
     */
    public AttackConfig(boolean ipSpoofing, boolean pathSwapping, boolean hopByHop,
                        boolean pathObfuscation, boolean methodTampering, boolean protocolDowngrade,
                        boolean suffixAttacks, boolean hide404, boolean hide403,
                        boolean caseSwitch, boolean unicodeNormalization, boolean backslashBypass,
                        boolean headerInjection, boolean activeMethodsEnabled,
                        int delayMs, int threadCount,
                        String ipListRaw, String pathListRaw) {
        this(ipSpoofing, pathSwapping, hopByHop, pathObfuscation, methodTampering,
                protocolDowngrade, suffixAttacks, hide404, hide403, caseSwitch,
                unicodeNormalization, backslashBypass, headerInjection,
                activeMethodsEnabled, "GET",
                delayMs, threadCount, ipListRaw, pathListRaw);
    }

    public AttackConfig(boolean ipSpoofing, boolean pathSwapping, boolean hopByHop,
                        boolean pathObfuscation, boolean methodTampering, boolean protocolDowngrade,
                        boolean suffixAttacks, boolean hide404, boolean hide403,
                        boolean caseSwitch, boolean unicodeNormalization, boolean backslashBypass,
                        boolean headerInjection, boolean activeMethodsEnabled, String targetMethod,
                        int delayMs, int threadCount,
                        String ipListRaw, String pathListRaw) {
        this.ipSpoofing = ipSpoofing;
        this.pathSwapping = pathSwapping;
        this.hopByHop = hopByHop;
        this.pathObfuscation = pathObfuscation;
        this.methodTampering = methodTampering;
        this.protocolDowngrade = protocolDowngrade;
        this.suffixAttacks = suffixAttacks;
        this.hide404 = hide404;
        this.hide403 = hide403;
        this.caseSwitch = caseSwitch;
        this.unicodeNormalization = unicodeNormalization;
        this.backslashBypass = backslashBypass;
        this.headerInjection = headerInjection;
        this.activeMethodsEnabled = activeMethodsEnabled;
        this.targetMethod = targetMethod == null ? "" : targetMethod.trim();
        this.delayMs = delayMs;
        this.threadCount = threadCount;
        this.userIPs = parseLines(ipListRaw);
        this.userPaths = parseLines(pathListRaw);
    }

    /**
     * Validates configuration. Returns list of error messages (empty = valid).
     */
    public List<String> validate() {
        List<String> errors = new ArrayList<>();
        if (delayMs < 0 || delayMs > 10000)
            errors.add("Request Delay must be between 0ms and 10000ms.");
        if (threadCount < 1 || threadCount > 50)
            errors.add("Thread count must be between 1 and 50.");
        if (userIPs.isEmpty() && isIpSpoofing())
            errors.add("IP Spoofing is enabled but the IP list is empty.");

        if (isSafeMode() && !RequestSafetyPolicy.isSafeAutomaticMethod(targetMethod)) {
            errors.add("Safe Mode will not transmit a " + targetMethod
                    + " target. Choose the Active Methods context-menu action explicitly for non-GET/HEAD/OPTIONS requests.");
        }

        boolean anyEnabled = isIpSpoofing() || isPathSwapping() || isHopByHop()
                || isPathObfuscation() || isMethodTampering() || isProtocolDowngrade()
                || isSuffixAttacks() || isCaseSwitch() || isUnicodeNormalization()
                || isBackslashBypass() || isHeaderInjection();
        if (!anyEnabled)
            errors.add(isSafeMode()
                    ? "No Safe Mode techniques are enabled. Method Tampering and the mixed Header Injection category require Active Methods."
                    : "At least one attack technique must be enabled.");
        return errors;
    }

    private static List<String> parseLines(String raw) {
        if (raw == null || raw.isBlank()) return new ArrayList<>();
        return Arrays.stream(raw.split("\\n"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
    }

    private boolean targetAllowedByMode() {
        return activeMethodsEnabled || RequestSafetyPolicy.isSafeAutomaticMethod(targetMethod);
    }

    // --- Effective technique getters consumed by PayloadGenerator ---
    public boolean isIpSpoofing() { return ipSpoofing && targetAllowedByMode(); }
    public boolean isPathSwapping() { return pathSwapping && targetAllowedByMode(); }
    public boolean isHopByHop() { return hopByHop && targetAllowedByMode(); }
    public boolean isPathObfuscation() { return pathObfuscation && targetAllowedByMode(); }

    // These categories currently contain non-GET/HEAD/OPTIONS requests. Keep them
    // completely out of Safe Mode until the generator is split into safe/active subfamilies.
    public boolean isMethodTampering() {
        return methodTampering && activeMethodsEnabled && targetAllowedByMode();
    }

    public boolean isProtocolDowngrade() { return protocolDowngrade && targetAllowedByMode(); }
    public boolean isSuffixAttacks() { return suffixAttacks && targetAllowedByMode(); }
    public boolean isHide404() { return hide404; }
    public boolean isHide403() { return hide403; }
    public boolean isCaseSwitch() { return caseSwitch && targetAllowedByMode(); }
    public boolean isUnicodeNormalization() { return unicodeNormalization && targetAllowedByMode(); }
    public boolean isBackslashBypass() { return backslashBypass && targetAllowedByMode(); }

    public boolean isHeaderInjection() {
        return headerInjection && activeMethodsEnabled && targetAllowedByMode();
    }

    public boolean isActiveMethodsEnabled() { return activeMethodsEnabled; }
    public boolean isSafeMode() { return !activeMethodsEnabled; }
    public String getTargetMethod() { return targetMethod; }
    public int getDelayMs() { return delayMs; }
    public int getThreadCount() { return threadCount; }
    public List<String> getUserIPs() { return userIPs; }
    public List<String> getUserPaths() { return userPaths; }
}
