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

    public BypassResult(int id, String method, String url, String technique, String category,
                        int status, int length, HttpRequestResponse requestResponse,
                        ResponseAnalyzer.ResultType classification, int confidence,
                        double bodySimilarity, String rationale) {
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

    /**
     * High-signal rows are candidates or redirects, never automatically confirmed vulnerabilities.
     */
    public boolean isInteresting() {
        return classification == ResponseAnalyzer.ResultType.BYPASS_CANDIDATE
                || classification == ResponseAnalyzer.ResultType.REDIRECT;
    }
}
