package com.bughunter;

import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * Immutable data class holding a single bypass attempt result.
 */
public class BypassResult {

    private final int id;
    private final String method;
    private final String url;
    private final String technique;
    private final String category;
    private final int status;
    private final int length;
    private final HttpRequestResponse requestResponse;
    private final ResponseAnalyzer.ResultType classification;
    private final int confidence;
    private final double bodySimilarity;
    private final String rationale;
    private final HttpRequestResponse controlRequestResponse;
    private final boolean controlCompared;
    private final int controlStatus;
    private final double controlSimilarity;
    private final boolean revalidationAttempted;
    private final int repeatabilityPasses;
    private final int repeatabilitySamples;
    private final String revalidationRationale;

    public BypassResult(int id, String method, String url, String technique, String category,
                        int status, int length, HttpRequestResponse requestResponse,
                        ResponseAnalyzer.ResultType classification, int confidence,
                        double bodySimilarity, String rationale) {
        this(id, method, url, technique, category, status, length, requestResponse,
                classification, confidence, bodySimilarity, rationale,
                null, false, -1, -1.0,
                false, 0, 1, "Revalidation not attempted");
    }

    public BypassResult(int id, String method, String url, String technique, String category,
                        int status, int length, HttpRequestResponse requestResponse,
                        ResponseAnalyzer.ResultType classification, int confidence,
                        double bodySimilarity, String rationale,
                        HttpRequestResponse controlRequestResponse, boolean controlCompared,
                        int controlStatus, double controlSimilarity) {
        this(id, method, url, technique, category, status, length, requestResponse,
                classification, confidence, bodySimilarity, rationale,
                controlRequestResponse, controlCompared, controlStatus, controlSimilarity,
                false, 0, 1, "Revalidation not attempted");
    }

    public BypassResult(int id, String method, String url, String technique, String category,
                        int status, int length, HttpRequestResponse requestResponse,
                        ResponseAnalyzer.ResultType classification, int confidence,
                        double bodySimilarity, String rationale,
                        HttpRequestResponse controlRequestResponse, boolean controlCompared,
                        int controlStatus, double controlSimilarity,
                        boolean revalidationAttempted, int repeatabilityPasses,
                        int repeatabilitySamples, String revalidationRationale) {
        this.id = id;
        this.method = method;
        this.url = url;
        this.technique = technique;
        this.category = category;
        this.status = status;
        this.length = length;
        this.requestResponse = requestResponse;
        this.classification = classification;
        this.confidence = confidence;
        this.bodySimilarity = bodySimilarity;
        this.rationale = rationale;
        this.controlRequestResponse = controlRequestResponse;
        this.controlCompared = controlCompared;
        this.controlStatus = controlStatus;
        this.controlSimilarity = controlSimilarity;
        this.revalidationAttempted = revalidationAttempted;
        this.repeatabilityPasses = repeatabilityPasses;
        this.repeatabilitySamples = repeatabilitySamples;
        this.revalidationRationale = revalidationRationale;
    }

    public int getId() { return id; }
    public String getMethod() { return method; }
    public String getUrl() { return url; }
    public String getTechnique() { return technique; }
    public String getCategory() { return category; }
    public int getStatus() { return status; }
    public int getLength() { return length; }
    public HttpRequestResponse getRequestResponse() { return requestResponse; }
    public ResponseAnalyzer.ResultType getClassification() { return classification; }
    public int getConfidence() { return confidence; }
    public double getBodySimilarity() { return bodySimilarity; }
    public String getRationale() { return rationale; }
    public HttpRequestResponse getControlRequestResponse() { return controlRequestResponse; }
    public boolean isControlCompared() { return controlCompared; }
    public int getControlStatus() { return controlStatus; }
    public double getControlSimilarity() { return controlSimilarity; }
    public boolean isRevalidationAttempted() { return revalidationAttempted; }
    public int getRepeatabilityPasses() { return repeatabilityPasses; }
    public int getRepeatabilitySamples() { return repeatabilitySamples; }
    public String getRevalidationRationale() { return revalidationRationale; }

    /**
     * High-signal rows are candidates or redirects, never automatically confirmed vulnerabilities.
     */
    public boolean isInteresting() {
        return classification == ResponseAnalyzer.ResultType.BYPASS_CANDIDATE
                || classification == ResponseAnalyzer.ResultType.REDIRECT;
    }
}
