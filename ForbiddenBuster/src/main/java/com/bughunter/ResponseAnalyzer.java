package com.bughunter;

/**
 * Analyzes HTTP responses to determine if a bypass was successful.
 * Compares against the baseline (original 403/401) to detect meaningful changes
 * and filter false positives.
 */
public class ResponseAnalyzer {

    private final short baselineStatus;
    private final int baselineLength;

    public ResponseAnalyzer(short baselineStatus, int baselineLength) {
        this.baselineStatus = baselineStatus;
        this.baselineLength = baselineLength;
    }

    /**
     * Determines if a response should be logged as interesting.
     *
     * @param status    HTTP status code of the response
     * @param length    Body length of the response
     * @param hide404   Whether to suppress 404 responses
     * @param hide403   Whether to suppress 403 responses
     * @return true if the response should be shown to the user
     */
    public boolean shouldLog(short status, int length, boolean hide404, boolean hide403) {
        if (hide404 && status == 404) return false;
        if (hide403 && status == 403) return false;

        // Status changed — always interesting
        if (status != baselineStatus) return true;

        // Same status but significant length difference (>10% or >100 bytes)
        int diff = Math.abs(length - baselineLength);
        double pctDiff = baselineLength > 0 ? (double) diff / baselineLength : diff;
        return diff > 100 || pctDiff > 0.10;
    }

    /**
     * Classifies how interesting a response is compared to baseline.
     *
     * @param status HTTP status code
     * @param length Body length
     * @return Classification: BYPASS, REDIRECT, ERROR, LENGTH_ANOMALY, NORMAL
     */
    public ResultType classify(short status, int length) {
        if (status >= 200 && status < 300 && baselineStatus >= 400) {
            return ResultType.BYPASS;
        }
        if (status >= 300 && status < 400 && baselineStatus >= 400) {
            return ResultType.REDIRECT;
        }
        if (status >= 500) {
            return ResultType.ERROR;
        }
        // Same status but length anomaly
        int diff = Math.abs(length - baselineLength);
        if (diff > 100 && status == baselineStatus) {
            return ResultType.LENGTH_ANOMALY;
        }
        return ResultType.NORMAL;
    }

    public short getBaselineStatus() { return baselineStatus; }
    public int getBaselineLength() { return baselineLength; }

    public enum ResultType {
        /** Status changed from 4xx to 2xx — confirmed bypass */
        BYPASS,
        /** Status changed from 4xx to 3xx — potential bypass via redirect */
        REDIRECT,
        /** Server error — worth investigating */
        ERROR,
        /** Same status but body length significantly changed */
        LENGTH_ANOMALY,
        /** No meaningful difference from baseline */
        NORMAL
    }
}
