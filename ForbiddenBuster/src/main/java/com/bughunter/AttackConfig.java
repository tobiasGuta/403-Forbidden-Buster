package com.bughunter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Immutable configuration holder for an attack run. Includes input validation.
 */
public class AttackConfig {

    // Toggle states
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

    // Scan settings
    private final int delayMs;
    private final int threadCount;

    // Custom lists
    private final List<String> userIPs;
    private final List<String> userPaths;

    public AttackConfig(boolean ipSpoofing, boolean pathSwapping, boolean hopByHop,
                        boolean pathObfuscation, boolean methodTampering, boolean protocolDowngrade,
                        boolean suffixAttacks, boolean hide404, boolean hide403,
                        boolean caseSwitch, boolean unicodeNormalization, boolean backslashBypass,
                        boolean headerInjection,
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
        if (userIPs.isEmpty() && ipSpoofing)
            errors.add("IP Spoofing is enabled but the IP list is empty.");

        boolean anyEnabled = ipSpoofing || pathSwapping || hopByHop || pathObfuscation
                || methodTampering || protocolDowngrade || suffixAttacks || caseSwitch
                || unicodeNormalization || backslashBypass || headerInjection;
        if (!anyEnabled)
            errors.add("At least one attack technique must be enabled.");
        return errors;
    }

    private static List<String> parseLines(String raw) {
        if (raw == null || raw.isBlank()) return new ArrayList<>();
        return Arrays.stream(raw.split("\\n"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
    }

    // --- Getters ---
    public boolean isIpSpoofing() { return ipSpoofing; }
    public boolean isPathSwapping() { return pathSwapping; }
    public boolean isHopByHop() { return hopByHop; }
    public boolean isPathObfuscation() { return pathObfuscation; }
    public boolean isMethodTampering() { return methodTampering; }
    public boolean isProtocolDowngrade() { return protocolDowngrade; }
    public boolean isSuffixAttacks() { return suffixAttacks; }
    public boolean isHide404() { return hide404; }
    public boolean isHide403() { return hide403; }
    public boolean isCaseSwitch() { return caseSwitch; }
    public boolean isUnicodeNormalization() { return unicodeNormalization; }
    public boolean isBackslashBypass() { return backslashBypass; }
    public boolean isHeaderInjection() { return headerInjection; }
    public int getDelayMs() { return delayMs; }
    public int getThreadCount() { return threadCount; }
    public List<String> getUserIPs() { return userIPs; }
    public List<String> getUserPaths() { return userPaths; }
}
