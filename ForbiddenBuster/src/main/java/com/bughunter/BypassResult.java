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
    private final boolean interesting;

    public BypassResult(int id, String method, String url, String technique, String category,
                        int status, int length, HttpRequestResponse requestResponse, boolean interesting) {
        this.id = id;
        this.method = method;
        this.url = url;
        this.technique = technique;
        this.category = category;
        this.status = status;
        this.length = length;
        this.requestResponse = requestResponse;
        this.interesting = interesting;
    }

    public int getId() { return id; }
    public String getMethod() { return method; }
    public String getUrl() { return url; }
    public String getTechnique() { return technique; }
    public String getCategory() { return category; }
    public int getStatus() { return status; }
    public int getLength() { return length; }
    public HttpRequestResponse getRequestResponse() { return requestResponse; }
    public boolean isInteresting() { return interesting; }
}
