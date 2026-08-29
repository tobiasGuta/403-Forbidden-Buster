package com.bughunter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Accuracy-focused HTTP response analyzer for v8.
 *
 * A status transition alone is never treated as proof of an authorization bypass.
 * The analyzer combines status, method semantics, normalized body similarity,
 * denial-marker behavior, baseline variance, paired controls, and body-length changes.
 */
public class ResponseAnalyzer {

    private static final Set<String> INFORMATIONAL_METHODS = Set.of(
            "HEAD", "OPTIONS", "TRACE", "CONNECT"
    );

    private static final String[] DENIAL_MARKERS = {
            "forbidden",
            "access denied",
            "unauthorized",
            "not authorized",
            "permission denied",
            "authentication required",
            "insufficient privileges"
    };

    private static final Pattern HTML_TAGS = Pattern.compile("<[^>]+>");
    private static final Pattern UUID = Pattern.compile(
            "\\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\b",
            Pattern.CASE_INSENSITIVE
    );
    private static final Pattern ISO_TIMESTAMP = Pattern.compile(
            "\\b\\d{4}-\\d{2}-\\d{2}[tT ][0-9:.+-]+(?:[zZ])?\\b"
    );
    private static final Pattern LONG_HEX = Pattern.compile("\\b[0-9a-f]{16,}\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern LONG_NUMBER = Pattern.compile("\\b\\d{6,}\\b");
    private static final Pattern NON_WORD = Pattern.compile("[^a-z0-9_<>]+", Pattern.CASE_INSENSITIVE);
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");

    private final short baselineStatus;
    private final int baselineLength;
    private final String baselineMethod;
    private final List<Integer> baselineLengths = new ArrayList<>();
    private final List<String> normalizedBaselineBodies = new ArrayList<>();
    private final List<Set<String>> baselineTokenSets = new ArrayList<>();
    private boolean baselineHasDenialMarker;

    public ResponseAnalyzer(short baselineStatus, int baselineLength) {
        this(baselineStatus, baselineLength, "", "GET");
    }

    public ResponseAnalyzer(short baselineStatus, int baselineLength, String baselineBody, String baselineMethod) {
        this.baselineStatus = baselineStatus;
        this.baselineLength = baselineLength;
        this.baselineMethod = normalizeMethod(baselineMethod);
        addBaselineData(baselineLength, baselineBody);
    }

    /**
     * Adds another unchanged baseline response. Returns false if its status does
     * not match the original baseline, because mixing authorization states would
     * make later comparisons unreliable.
     */
    public boolean addBaselineSample(short status, int length, String body) {
        if (status != baselineStatus) return false;
        addBaselineData(length, body);
        return true;
    }

    private void addBaselineData(int length, String body) {
        String normalized = normalizeBody(body);
        baselineLengths.add(length);
        normalizedBaselineBodies.add(normalized);
        baselineTokenSets.add(tokenize(normalized));
        baselineHasDenialMarker = baselineHasDenialMarker || containsDenialMarker(normalized);
    }

    /**
     * Analyze one mutated response against the calibrated denied baseline.
     */
    public Analysis analyze(String requestMethod, short status, int length, String body,
                            boolean hide404, boolean hide403) {
        if ((hide404 && status == 404) || (hide403 && status == 403)) {
            return analysis(ResultType.NORMAL, 0, 1.0, false,
                    "Filtered by user configuration", false);
        }

        String method = normalizeMethod(requestMethod);
        String normalizedBody = normalizeBody(body);
        double similarity = bodySimilarityToBaselines(normalizedBody);
        boolean significantLengthDifference = isSignificantLengthDifference(length);
        boolean currentHasDenialMarker = containsDenialMarker(normalizedBody);
        boolean denialMarkerDisappeared = baselineHasDenialMarker && !currentHasDenialMarker;
        boolean bodyIsEmpty = normalizedBody.isBlank();

        ResultType type;
        int confidence = 0;
        String rationale;

        if (status >= 500) {
            type = ResultType.ERROR;
            rationale = "Server error response";
        } else if (baselineStatus >= 400 && status >= 200 && status < 300) {
            confidence = score2xxTransition(method, status, similarity,
                    significantLengthDifference, denialMarkerDisappeared, bodyIsEmpty);

            if (INFORMATIONAL_METHODS.contains(method)) {
                type = ResultType.METHOD_BEHAVIOR;
                rationale = method + " returned 2xx; method semantics require manual validation";
            } else if (confidence >= 60) {
                type = ResultType.BYPASS_CANDIDATE;
                rationale = "2xx plus meaningful response differences; manual authorization validation required";
            } else {
                type = ResultType.STATUS_ANOMALY;
                rationale = "2xx transition without enough evidence to call a bypass candidate";
            }
        } else if (baselineStatus >= 400 && status >= 300 && status < 400) {
            type = ResultType.REDIRECT;
            confidence = Math.min(45, 15 + (similarity < 0.70 ? 15 : 0)
                    + (denialMarkerDisappeared ? 10 : 0)
                    + (significantLengthDifference ? 5 : 0));
            rationale = "Redirect from a denied baseline; destination must be inspected manually";
        } else if (status != baselineStatus) {
            type = ResultType.STATUS_ANOMALY;
            confidence = 15;
            rationale = "HTTP status differs from baseline";
        } else if (similarity < 0.80) {
            type = ResultType.BODY_ANOMALY;
            confidence = similarity < 0.40 ? 35 : 20;
            rationale = "Response body differs materially from all baseline samples";
        } else if (significantLengthDifference) {
            type = ResultType.LENGTH_ANOMALY;
            confidence = 15;
            rationale = "Response length differs materially from all baseline samples";
        } else {
            type = ResultType.NORMAL;
            rationale = "No meaningful difference from calibrated baseline";
        }

        boolean shouldLog = type != ResultType.NORMAL;
        return analysis(type, clamp(confidence), similarity,
                significantLengthDifference, rationale, shouldLog);
    }

    /**
     * Analyze a mutation against both the denied baseline and a neutral paired
     * control. Controls may neutralize a routing header or preserve a routing
     * mutation while moving to a synthetic non-target path. Either way, a
     * candidate that matches the control is evidence of routing-surface behavior,
     * not protected-resource access.
     */
    public Analysis analyzeWithControl(String requestMethod,
                                       short status, int length, String body,
                                       short controlStatus, int controlLength, String controlBody,
                                       boolean hide404, boolean hide403) {
        Analysis baselineAnalysis = analyze(
                requestMethod, status, length, body, hide404, hide403
        );

        double controlSimilarity = bodySimilarity(controlBody, body);
        boolean controlLengthDifference = isSignificantAgainst(controlLength, length);
        boolean sameControlStatus = status == controlStatus;
        String method = normalizeMethod(requestMethod);

        // A 2xx mutation that is effectively identical to its neutral control is
        // not evidence of protected-resource access. This catches ignored routing
        // signals as well as generic/default-vhost and catch-all responses.
        if (status >= 200 && status < 300
                && controlStatus >= 200 && controlStatus < 300
                && sameControlStatus
                && controlSimilarity >= 0.90
                && !controlLengthDifference) {
            return new Analysis(
                    ResultType.CONTROL_MATCH,
                    0,
                    baselineAnalysis.bodySimilarity(),
                    baselineAnalysis.significantLengthDifference(),
                    "Candidate matches paired control; response likely reflects generic routing-surface behavior rather than protected-resource access",
                    false,
                    true,
                    controlSimilarity,
                    controlStatus
            );
        }

        ResultType type = baselineAnalysis.type();
        int confidence = baselineAnalysis.confidence();
        String rationale = baselineAnalysis.rationale();

        // For ordinary 2xx methods, a response that differs from the neutral
        // control is positive differential evidence. Conversely, a near-match
        // reduces confidence even when it is not similar enough to suppress.
        if (baselineStatus >= 400 && status >= 200 && status < 300
                && !INFORMATIONAL_METHODS.contains(method)) {
            if (controlStatus < 200 || controlStatus >= 300) confidence += 20;

            if (controlSimilarity < 0.35) confidence += 25;
            else if (controlSimilarity < 0.70) confidence += 15;
            else if (controlSimilarity < 0.90) confidence += 5;
            else if (controlSimilarity >= 0.97) confidence -= 25;

            if (controlLengthDifference) confidence += 10;
            if (!sameControlStatus) confidence += 10;

            confidence = clamp(confidence);
            if (confidence >= 60) {
                type = ResultType.BYPASS_CANDIDATE;
            } else if (type == ResultType.BYPASS_CANDIDATE) {
                type = ResultType.STATUS_ANOMALY;
            }
        } else if (type == ResultType.REDIRECT) {
            // Do not suppress redirects from body similarity alone because the
            // Location header is not part of the v8 comparator yet.
            if (!sameControlStatus) confidence += 10;
            if (controlSimilarity < 0.70) confidence += 10;
            confidence = Math.min(55, clamp(confidence));
        }

        rationale = rationale
                + "; paired control status=" + controlStatus
                + ", body similarity=" + Math.round(controlSimilarity * 100.0) + "%";

        return new Analysis(
                type,
                confidence,
                baselineAnalysis.bodySimilarity(),
                baselineAnalysis.significantLengthDifference(),
                rationale,
                baselineAnalysis.shouldLog(),
                true,
                controlSimilarity,
                controlStatus
        );
    }

    private static Analysis analysis(ResultType type, int confidence, double bodySimilarity,
                                     boolean significantLengthDifference, String rationale,
                                     boolean shouldLog) {
        return new Analysis(
                type,
                confidence,
                bodySimilarity,
                significantLengthDifference,
                rationale,
                shouldLog,
                false,
                -1.0,
                -1
        );
    }

    /**
     * Retained for compatibility with older callers.
     */
    public boolean shouldLog(short status, int length, boolean hide404, boolean hide403) {
        return analyze(baselineMethod, status, length, "", hide404, hide403).shouldLog();
    }

    /**
     * Retained for compatibility with older callers.
     */
    public ResultType classify(short status, int length) {
        return analyze(baselineMethod, status, length, "", false, false).type();
    }

    /**
     * A candidate length is considered anomalous only when it falls outside the
     * tolerated range of every captured baseline sample.
     */
    public boolean isSignificantLengthDifference(int length) {
        for (int sampleLength : baselineLengths) {
            if (!isSignificantAgainst(sampleLength, length)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isSignificantAgainst(int referenceLength, int candidateLength) {
        int diff = Math.abs(candidateLength - referenceLength);
        double pctDiff = referenceLength > 0
                ? (double) diff / referenceLength
                : (diff > 0 ? 1.0 : 0.0);
        return diff > 100 || pctDiff > 0.10;
    }

    private double bodySimilarityToBaselines(String normalizedCandidate) {
        double best = 0.0;
        for (int i = 0; i < normalizedBaselineBodies.size(); i++) {
            double similarity = bodySimilarity(
                    normalizedBaselineBodies.get(i),
                    baselineTokenSets.get(i),
                    normalizedCandidate
            );
            if (similarity > best) best = similarity;
            if (best >= 1.0) return 1.0;
        }
        return best;
    }

    private int score2xxTransition(String method, short status, double similarity,
                                   boolean significantLengthDifference,
                                   boolean denialMarkerDisappeared,
                                   boolean bodyIsEmpty) {
        int score = 35;

        if (method.equals(baselineMethod)) {
            score += 15;
        } else if (INFORMATIONAL_METHODS.contains(method)) {
            score -= 30;
        } else {
            score += 5;
        }

        if (similarity < 0.35) score += 25;
        else if (similarity < 0.70) score += 15;
        else if (similarity < 0.90) score += 5;
        else if (similarity >= 0.97) score -= 15;

        if (denialMarkerDisappeared) score += 15;
        if (significantLengthDifference) score += 10;
        if (bodyIsEmpty) score -= 20;
        if (status == 204) score -= 20;

        return clamp(score);
    }

    private static int clamp(int value) {
        return Math.max(0, Math.min(100, value));
    }

    private static String normalizeMethod(String method) {
        return method == null ? "" : method.trim().toUpperCase(Locale.ROOT);
    }

    public int getBaselineSampleCount() {
        return baselineLengths.size();
    }

    public short getBaselineStatus() { return baselineStatus; }
    public int getBaselineLength() { return baselineLength; }

    static String normalizeBody(String body) {
        if (body == null || body.isBlank()) return "";

        String normalized = body.toLowerCase(Locale.ROOT);
        normalized = HTML_TAGS.matcher(normalized).replaceAll(" ");
        normalized = UUID.matcher(normalized).replaceAll(" <uuid> ");
        normalized = ISO_TIMESTAMP.matcher(normalized).replaceAll(" <timestamp> ");
        normalized = LONG_HEX.matcher(normalized).replaceAll(" <hex> ");
        normalized = LONG_NUMBER.matcher(normalized).replaceAll(" <number> ");
        normalized = NON_WORD.matcher(normalized).replaceAll(" ");
        normalized = WHITESPACE.matcher(normalized).replaceAll(" ").trim();
        return normalized;
    }

    private static boolean containsDenialMarker(String normalizedBody) {
        for (String marker : DENIAL_MARKERS) {
            if (normalizedBody.contains(marker)) return true;
        }
        return false;
    }

    private static Set<String> tokenize(String normalizedBody) {
        if (normalizedBody == null || normalizedBody.isBlank()) return Set.of();
        return new HashSet<>(Arrays.asList(normalizedBody.split(" ")));
    }

    public static double bodySimilarity(String left, String right) {
        String normalizedLeft = normalizeBody(left);
        return bodySimilarity(normalizedLeft, tokenize(normalizedLeft), normalizeBody(right));
    }

    private static double bodySimilarity(String normalizedLeft, Set<String> leftTokens,
                                         String normalizedRight) {
        if (normalizedLeft.equals(normalizedRight)) return 1.0;
        Set<String> rightTokens = tokenize(normalizedRight);
        if (leftTokens.isEmpty() && rightTokens.isEmpty()) return 1.0;
        if (leftTokens.isEmpty() || rightTokens.isEmpty()) return 0.0;

        Set<String> intersection = new HashSet<>(leftTokens);
        intersection.retainAll(rightTokens);
        Set<String> union = new HashSet<>(leftTokens);
        union.addAll(rightTokens);
        return union.isEmpty() ? 1.0 : (double) intersection.size() / union.size();
    }

    public enum ResultType {
        BYPASS_CANDIDATE,
        REDIRECT,
        METHOD_BEHAVIOR,
        ERROR,
        BODY_ANOMALY,
        LENGTH_ANOMALY,
        STATUS_ANOMALY,
        CONTROL_MATCH,
        NORMAL
    }

    public record Analysis(ResultType type,
                           int confidence,
                           double bodySimilarity,
                           boolean significantLengthDifference,
                           String rationale,
                           boolean shouldLog,
                           boolean controlCompared,
                           double controlSimilarity,
                           int controlStatus) {
        public boolean interesting() {
            return type == ResultType.BYPASS_CANDIDATE || type == ResultType.REDIRECT;
        }
    }
}
