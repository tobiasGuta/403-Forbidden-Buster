package com.bughunter;

/**
 * Per-target v8 execution mode selected from Burp's context menu.
 *
 * Active Methods is intentionally not persisted. Selecting the normal context
 * menu item always returns the current target to Safe Mode.
 */
final class ActiveMethodsRegistry {

    private static volatile boolean activeMethodsEnabled = false;
    private static volatile String targetMethod = "GET";

    private ActiveMethodsRegistry() {}

    static void configure(boolean activeMethods, String method) {
        activeMethodsEnabled = activeMethods;
        targetMethod = method == null ? "" : method.trim();
    }

    static boolean isActiveMethodsEnabled() {
        return activeMethodsEnabled;
    }

    static String targetMethod() {
        return targetMethod;
    }

    static void reset() {
        activeMethodsEnabled = false;
        targetMethod = "GET";
    }
}
