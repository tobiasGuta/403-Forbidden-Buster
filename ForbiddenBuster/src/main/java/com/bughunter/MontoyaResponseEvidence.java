package com.bughunter;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.responses.analysis.ResponseKeywordsAnalyzer;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Supplemental v8 evidence backed by Burp's native response analyzers.
 *
 * The custom ResponseAnalyzer remains authoritative for classification. This
 * class only records semantic attributes and denial-keyword counts that move
 * outside the calibrated baseline profile, plus candidate/control differences.
 * It is deliberately fail-open for analysis errors: a Montoya analyzer failure
 * must never abort or promote a scan result.
 */
final class MontoyaResponseEvidence {

    private static final Set<AttributeType> RELEVANT_ATTRIBUTES = EnumSet.of(
            AttributeType.STATUS_CODE,
            AttributeType.CONTENT_TYPE,
            AttributeType.CONTENT_LENGTH,
            AttributeType.BODY_CONTENT,
            AttributeType.LIMITED_BODY_CONTENT,
            AttributeType.VISIBLE_TEXT,
            AttributeType.WORD_COUNT,
            AttributeType.VISIBLE_WORD_COUNT,
            AttributeType.PAGE_TITLE,
            AttributeType.LOCATION,
            AttributeType.CONTENT_LOCATION,
            AttributeType.HEADER_NAMES,
            AttributeType.COOKIE_NAMES,
            AttributeType.ETAG_HEADER,
            AttributeType.LAST_MODIFIED_HEADER
    );

    private static final List<String> DENIAL_KEYWORDS = List.of(
            "forbidden",
            "access denied",
            "unauthorized",
            "not authorized",
            "permission denied",
            "authentication required",
            "insufficient privileges"
    );

    private final Http http;
    private final List<HttpResponse> baselineResponses = new ArrayList<>();

    MontoyaResponseEvidence(Http http, HttpResponse capturedBaseline) {
        this.http = http;
        if (capturedBaseline != null) baselineResponses.add(capturedBaseline);
    }

    synchronized void addBaseline(HttpResponse response) {
        if (response != null) baselineResponses.add(response);
    }

    synchronized int baselineSampleCount() {
        return baselineResponses.size();
    }

    synchronized Evidence compare(HttpResponse candidate, HttpResponse control) {
        if (candidate == null) return Evidence.unavailable("No candidate response was available");

        try {
            List<HttpResponse> baselines = List.copyOf(baselineResponses);
            Set<AttributeType> stableBaselineAttributes = invariantAttributes(baselines);
            Set<String> stableBaselineKeywords = invariantKeywords(baselines);

            List<HttpResponse> candidateSeries = new ArrayList<>(baselines);
            candidateSeries.add(candidate);

            Set<AttributeType> candidateVariants = relevant(variantAttributes(candidateSeries));
            candidateVariants.retainAll(stableBaselineAttributes);

            Set<String> denialKeywordVariants = new LinkedHashSet<>(variantKeywords(candidateSeries));
            denialKeywordVariants.retainAll(stableBaselineKeywords);

            Set<AttributeType> controlVariants = Set.of();
            Set<String> controlKeywordVariants = Set.of();
            if (control != null) {
                controlVariants = relevant(variantAttributes(List.of(candidate, control)));
                controlKeywordVariants = new LinkedHashSet<>(variantKeywords(List.of(candidate, control)));
            }

            String candidateLocation = nullToEmpty(candidate.headerValue("Location"));
            String controlLocation = control == null ? "" : nullToEmpty(control.headerValue("Location"));

            return new Evidence(
                    true,
                    Set.copyOf(candidateVariants),
                    Set.copyOf(denialKeywordVariants),
                    Set.copyOf(controlVariants),
                    Set.copyOf(controlKeywordVariants),
                    candidateLocation,
                    controlLocation,
                    ""
            );
        } catch (RuntimeException e) {
            return Evidence.unavailable("Montoya semantic analysis unavailable: " + safeMessage(e));
        }
    }

    private Set<AttributeType> invariantAttributes(List<HttpResponse> responses) {
        if (responses.isEmpty()) return Set.of();
        ResponseVariationsAnalyzer analyzer = http.createResponseVariationsAnalyzer();
        for (HttpResponse response : responses) analyzer.updateWith(response);
        return relevant(analyzer.invariantAttributes());
    }

    private Set<String> invariantKeywords(List<HttpResponse> responses) {
        if (responses.isEmpty()) return Set.of();
        ResponseKeywordsAnalyzer analyzer = http.createResponseKeywordsAnalyzer(DENIAL_KEYWORDS);
        for (HttpResponse response : responses) analyzer.updateWith(response);
        return new LinkedHashSet<>(analyzer.invariantKeywords());
    }

    private Set<AttributeType> variantAttributes(List<HttpResponse> responses) {
        if (responses.size() < 2) return Set.of();
        ResponseVariationsAnalyzer analyzer = http.createResponseVariationsAnalyzer();
        for (HttpResponse response : responses) analyzer.updateWith(response);
        return new LinkedHashSet<>(analyzer.variantAttributes());
    }

    private Set<String> variantKeywords(List<HttpResponse> responses) {
        if (responses.size() < 2) return Set.of();
        ResponseKeywordsAnalyzer analyzer = http.createResponseKeywordsAnalyzer(DENIAL_KEYWORDS);
        for (HttpResponse response : responses) analyzer.updateWith(response);
        return new LinkedHashSet<>(analyzer.variantKeywords());
    }

    private static Set<AttributeType> relevant(Set<AttributeType> attributes) {
        if (attributes == null || attributes.isEmpty()) return new LinkedHashSet<>();
        Set<AttributeType> filtered = EnumSet.noneOf(AttributeType.class);
        filtered.addAll(attributes);
        filtered.retainAll(RELEVANT_ATTRIBUTES);
        return filtered;
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value.trim();
    }

    private static String safeMessage(RuntimeException e) {
        String message = e.getMessage();
        return message == null || message.isBlank() ? e.getClass().getSimpleName() : message;
    }

    record Evidence(
            boolean available,
            Set<AttributeType> baselineStableVariants,
            Set<String> denialKeywordVariants,
            Set<AttributeType> controlVariants,
            Set<String> controlKeywordVariants,
            String candidateLocation,
            String controlLocation,
            String note
    ) {
        static Evidence unavailable(String note) {
            return new Evidence(false, Set.of(), Set.of(), Set.of(), Set.of(), "", "", note);
        }

        String summary() {
            if (!available) return note;

            List<String> parts = new ArrayList<>();
            if (!baselineStableVariants.isEmpty()) {
                parts.add("stable-baseline variants=" + formatAttributes(baselineStableVariants));
            }
            if (!denialKeywordVariants.isEmpty()) {
                parts.add("denial-keyword count variants=" + formatStrings(denialKeywordVariants));
            }
            if (!controlVariants.isEmpty()) {
                parts.add("candidate/control variants=" + formatAttributes(controlVariants));
            }
            if (!controlKeywordVariants.isEmpty()) {
                parts.add("candidate/control denial-keyword variants=" + formatStrings(controlKeywordVariants));
            }
            return parts.isEmpty() ? "No selected Montoya semantic variations" : String.join("; ", parts);
        }

        boolean locationVariesFromStableBaseline() {
            return baselineStableVariants.contains(AttributeType.LOCATION);
        }

        boolean locationVariesFromControl() {
            return controlVariants.contains(AttributeType.LOCATION);
        }
    }

    static String formatAttributes(Set<AttributeType> attributes) {
        if (attributes == null || attributes.isEmpty()) return "none";
        return attributes.stream()
                .sorted(Comparator.comparing(Enum::name))
                .map(Enum::name)
                .collect(Collectors.joining("|"));
    }

    static String formatStrings(Set<String> values) {
        if (values == null || values.isEmpty()) return "none";
        return values.stream().sorted().collect(Collectors.joining("|"));
    }
}
