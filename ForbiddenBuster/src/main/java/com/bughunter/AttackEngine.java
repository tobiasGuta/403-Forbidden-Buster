package com.bughunter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Manages attack execution with thread pool, pause/resume/stop controls,
 * global rate limiting, calibrated v8 response analysis, paired controls,
 * Montoya semantic evidence, safe candidate revalidation, and progress reporting.
 */
public class AttackEngine {

    private static final int SAFE_GET_BASELINE_REPLAYS = 2;
    private static final int SAFE_CANDIDATE_REPLAYS = 2;

    public interface AttackListener {
        void onResult(BypassResult result);
        void onProgressUpdate(int completed, int total);
        void onAttackStarted(int totalPayloads);
        void onAttackComplete();
        void onError(String technique, String errorMessage);
    }

    private final MontoyaApi api;
    private final AttackListener listener;
    private final AtomicInteger idCounter = new AtomicInteger(1);

    private volatile boolean isRunning = false;
    private volatile boolean isPaused = false;
    private ExecutorService executor;
    private Thread coordinatorThread;

    // Global rate limiter — shared across calibration, controls, revalidation, and attack workers.
    private volatile long lastRequestTimeMs = 0;
    private final Object rateLock = new Object();

    public AttackEngine(MontoyaApi api, AttackListener listener) {
        this.api = api;
        this.listener = listener;
    }

    public boolean isRunning() { return isRunning; }
    public boolean isPaused() { return isPaused; }

    public void togglePause() {
        isPaused = !isPaused;
        api.logging().logToOutput(isPaused ? "[403 Buster] Attack Paused." : "[403 Buster] Attack Resumed.");
    }

    public void stop() {
        isRunning = false;
        isPaused = false;
        if (executor != null && !executor.isShutdown()) {
            executor.shutdownNow();
        }
        if (coordinatorThread != null) {
            coordinatorThread.interrupt();
        }
        api.logging().logToOutput("[403 Buster] Attack Stopped by user.");
    }

    public void startAttack(HttpRequestResponse baseRequestResponse, AttackConfig config) {
        if (isRunning) {
            api.logging().logToOutput("[403 Buster] Attack already running. Stop it first.");
            return;
        }

        isRunning = true;
        isPaused = false;
        lastRequestTimeMs = 0;

        coordinatorThread = new Thread(() -> {
            try {
                executeAttack(baseRequestResponse, config);
            } finally {
                isRunning = false;
                isPaused = false;
                if (executor != null) executor.shutdown();
                listener.onAttackComplete();
                api.logging().logToOutput("[403 Buster] Attack finished.");
            }
        }, "403Buster-Coordinator");
        coordinatorThread.setDaemon(true);
        coordinatorThread.start();
    }

    private void executeAttack(HttpRequestResponse baseRequestResponse, AttackConfig config) {
        short baseStatus = baseRequestResponse.response().statusCode();
        if (baseStatus != 401 && baseStatus != 403) {
            String message = "Target baseline must be 401 or 403, got " + baseStatus + ".";
            listener.onError("Baseline", message);
            api.logging().logToError("[403 Buster] " + message);
            return;
        }

        int baseLength = baseRequestResponse.response().body().length();
        String baseBody = baseRequestResponse.response().bodyToString();
        String baseMethod = baseRequestResponse.request().method();
        ResponseAnalyzer analyzer = new ResponseAnalyzer(baseStatus, baseLength, baseBody, baseMethod);
        MontoyaResponseEvidence montoyaEvidence = new MontoyaResponseEvidence(
                api.http(), baseRequestResponse.response()
        );

        if (!calibrateBaseline(baseRequestResponse, analyzer, montoyaEvidence, config)) {
            return;
        }

        List<PayloadGenerator.Payload> generatedPayloads = PayloadGenerator.generate(baseRequestResponse, config);
        List<PayloadGenerator.Payload> payloads = new ArrayList<>();
        int semanticSkips = 0;
        int unsafeControlSkips = 0;

        for (PayloadGenerator.Payload payload : generatedPayloads) {
            PairedControlPlanner.Plan plan = PairedControlPlanner.plan(
                    baseRequestResponse,
                    payload,
                    config.isActiveMethodsEnabled()
            );
            if (plan.shouldSkip()) {
                semanticSkips++;
                continue;
            }
            if (plan.requiresControl() && !isSafeAutomaticControlMethod(plan.controlRequest())) {
                unsafeControlSkips++;
                continue;
            }
            payloads.add(payload);
        }

        if (semanticSkips > 0) {
            api.logging().logToOutput("[403 Buster] Skipped " + semanticSkips
                    + " payload(s) at semantic-target or Safe Mode gates.");
        }
        if (unsafeControlSkips > 0) {
            api.logging().logToOutput("[403 Buster] Skipped " + unsafeControlSkips
                    + " control-required payload(s) because the neutral control would replay a state-changing method.");
        }

        int total = payloads.size();
        if (total == 0) {
            api.logging().logToOutput("[403 Buster] No payloads remained after v8 safety and accuracy gates.");
            listener.onAttackStarted(0);
            return;
        }

        api.logging().logToOutput("[403 Buster] Starting attack with " + total + " payloads | " +
                config.getThreadCount() + " threads | " + config.getDelayMs() + "ms delay | " +
                analyzer.getBaselineSampleCount() + " baseline sample(s) | Montoya semantic profile="
                + montoyaEvidence.baselineSampleCount() + " sample(s)");

        listener.onAttackStarted(total);

        executor = Executors.newFixedThreadPool(config.getThreadCount(), r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });

        AtomicInteger completed = new AtomicInteger(0);

        for (PayloadGenerator.Payload payload : payloads) {
            if (!isRunning) break;
            if (!waitUntilRunnable()) break;

            executor.submit(() -> {
                try {
                    PairedControlPlanner.Plan plan = PairedControlPlanner.plan(
                            baseRequestResponse,
                            payload,
                            config.isActiveMethodsEnabled()
                    );
                    if (plan.shouldSkip()) return;

                    HttpRequestResponse controlResponse = null;
                    if (plan.requiresControl()) {
                        controlResponse = sendRateLimited(plan.controlRequest(), config.getDelayMs());
                        if (controlResponse == null) return;
                    }

                    HttpRequestResponse response = sendRateLimited(payload.request, config.getDelayMs());
                    if (response == null) return;

                    short statusCode = response.response().statusCode();
                    int length = response.response().body().length();

                    ResponseAnalyzer.Analysis analysis = analyzeResponse(
                            analyzer,
                            montoyaEvidence,
                            payload,
                            response,
                            controlResponse,
                            config
                    );

                    if (analysis.shouldLog()) {
                        CandidateRevalidation.Summary revalidation;
                        if (analysis.type() == ResponseAnalyzer.ResultType.BYPASS_CANDIDATE) {
                            if (isSafeAutomaticRevalidationMethod(payload.request)) {
                                revalidation = revalidateCandidate(
                                        payload,
                                        plan,
                                        analyzer,
                                        montoyaEvidence,
                                        response,
                                        analysis,
                                        config
                                );
                                if (revalidation == null) return;
                            } else {
                                revalidation = CandidateRevalidation.Summary.skipped(
                                        analysis.type(),
                                        analysis.confidence(),
                                        "Automatic revalidation skipped for " + payload.request.method()
                                                + " to avoid repeated state-changing requests"
                                );
                            }
                        } else {
                            revalidation = CandidateRevalidation.Summary.skipped(
                                    analysis.type(),
                                    analysis.confidence(),
                                    "Revalidation not required for " + analysis.type()
                            );
                        }

                        ResponseAnalyzer.ResultType finalClassification = revalidation.attempted()
                                ? revalidation.classification()
                                : analysis.type();
                        int finalConfidence = revalidation.attempted()
                                ? revalidation.confidence()
                                : analysis.confidence();
                        String finalRationale = analysis.rationale();
                        if (analysis.type() == ResponseAnalyzer.ResultType.BYPASS_CANDIDATE) {
                            finalRationale = finalRationale + "; " + revalidation.rationale();
                        }

                        BypassResult result = new BypassResult(
                                idCounter.getAndIncrement(),
                                payload.request.method(),
                                payload.request.url(),
                                payload.description,
                                payload.category,
                                statusCode,
                                length,
                                response,
                                finalClassification,
                                finalConfidence,
                                analysis.bodySimilarity(),
                                finalRationale,
                                controlResponse,
                                analysis.controlCompared(),
                                analysis.controlStatus(),
                                analysis.controlSimilarity(),
                                revalidation.attempted(),
                                revalidation.consistentPasses(),
                                revalidation.totalSamples(),
                                revalidation.rationale()
                        );
                        listener.onResult(result);
                    }
                } catch (Exception e) {
                    if (isRunning) {
                        listener.onError(payload.description, e.getMessage());
                        api.logging().logToError("[403 Buster] Error: " + payload.description + " — " + e.getMessage());
                    }
                } finally {
                    int done = completed.incrementAndGet();
                    listener.onProgressUpdate(done, total);
                }
            });
        }

        executor.shutdown();
        try {
            while (!executor.isTerminated()) {
                if (!isRunning) {
                    executor.shutdownNow();
                    break;
                }
                Thread.sleep(200);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            executor.shutdownNow();
        }
    }

    private ResponseAnalyzer.Analysis analyzeResponse(ResponseAnalyzer analyzer,
                                                      MontoyaResponseEvidence montoyaEvidence,
                                                      PayloadGenerator.Payload payload,
                                                      HttpRequestResponse response,
                                                      HttpRequestResponse controlResponse,
                                                      AttackConfig config) {
        short statusCode = response.response().statusCode();
        int length = response.response().body().length();
        String body = response.response().bodyToString();
        String location = response.response().headerValue("Location");
        String controlLocation = controlResponse == null
                ? ""
                : controlResponse.response().headerValue("Location");

        ResponseAnalyzer.Analysis analysis;
        if (controlResponse != null) {
            analysis = analyzer.analyzeWithControl(
                    payload.request.method(),
                    statusCode,
                    length,
                    body,
                    location,
                    controlResponse.response().statusCode(),
                    controlResponse.response().body().length(),
                    controlResponse.response().bodyToString(),
                    controlLocation,
                    config.isHide404(),
                    config.isHide403()
            );
        } else {
            analysis = analyzer.analyze(
                    payload.request.method(),
                    statusCode,
                    length,
                    body,
                    location,
                    config.isHide404(),
                    config.isHide403()
            );
        }

        MontoyaResponseEvidence.Evidence semantic = montoyaEvidence.compare(
                response.response(),
                controlResponse == null ? null : controlResponse.response()
        );
        return appendSemanticEvidence(analysis, semantic);
    }

    private static ResponseAnalyzer.Analysis appendSemanticEvidence(
            ResponseAnalyzer.Analysis analysis,
            MontoyaResponseEvidence.Evidence semantic) {
        StringBuilder extra = new StringBuilder("Montoya semantic evidence: ")
                .append(semantic.summary());

        if (semantic.available() && !semantic.candidateLocation().isBlank()) {
            extra.append("; Location=").append(ResponseAnalyzer.normalizeLocation(semantic.candidateLocation()));
            if (semantic.locationVariesFromStableBaseline()) {
                extra.append(" (varies from stable baseline)");
            }
        }
        if (semantic.available() && !semantic.controlLocation().isBlank()) {
            extra.append("; control Location=")
                    .append(ResponseAnalyzer.normalizeLocation(semantic.controlLocation()));
            if (semantic.locationVariesFromControl()) {
                extra.append(" (candidate/control differ)");
            }
        }

        return new ResponseAnalyzer.Analysis(
                analysis.type(),
                analysis.confidence(),
                analysis.bodySimilarity(),
                analysis.significantLengthDifference(),
                analysis.rationale() + "; " + extra,
                analysis.shouldLog(),
                analysis.controlCompared(),
                analysis.controlSimilarity(),
                analysis.controlStatus()
        );
    }

    private CandidateRevalidation.Summary revalidateCandidate(PayloadGenerator.Payload payload,
                                                               PairedControlPlanner.Plan plan,
                                                               ResponseAnalyzer analyzer,
                                                               MontoyaResponseEvidence montoyaEvidence,
                                                               HttpRequestResponse initialResponse,
                                                               ResponseAnalyzer.Analysis initialAnalysis,
                                                               AttackConfig config) {
        List<CandidateRevalidation.Observation> observations = new ArrayList<>();
        short initialStatus = initialResponse.response().statusCode();
        String initialBody = initialResponse.response().bodyToString();

        api.logging().logToOutput("[403 Buster] Revalidating candidate: "
                + payload.description + " with " + SAFE_CANDIDATE_REPLAYS + " safe replay(s).");

        for (int i = 0; i < SAFE_CANDIDATE_REPLAYS; i++) {
            if (!isRunning) return null;

            try {
                HttpRequestResponse freshControl = null;
                if (plan.requiresControl()) {
                    freshControl = sendRateLimited(plan.controlRequest(), config.getDelayMs());
                    if (freshControl == null) return null;
                }

                HttpRequestResponse replay = sendRateLimited(payload.request, config.getDelayMs());
                if (replay == null) return null;

                ResponseAnalyzer.Analysis replayAnalysis = analyzeResponse(
                        analyzer,
                        montoyaEvidence,
                        payload,
                        replay,
                        freshControl,
                        config
                );

                observations.add(new CandidateRevalidation.Observation(
                        replay.response().statusCode(),
                        replay.response().bodyToString(),
                        replayAnalysis
                ));
            } catch (Exception e) {
                String message = "Candidate revalidation replay failed: " + e.getMessage();
                listener.onError(payload.description, message);
                api.logging().logToError("[403 Buster] " + message);
                break;
            }
        }

        return CandidateRevalidation.summarize(
                initialStatus,
                initialBody,
                initialAnalysis,
                observations,
                SAFE_CANDIDATE_REPLAYS
        );
    }

    private boolean calibrateBaseline(HttpRequestResponse baseRequestResponse,
                                      ResponseAnalyzer analyzer,
                                      MontoyaResponseEvidence montoyaEvidence,
                                      AttackConfig config) {
        String method = baseRequestResponse.request().method();
        if (!"GET".equalsIgnoreCase(method)) {
            api.logging().logToOutput(
                    "[403 Buster] Baseline replay skipped for " + method + " to avoid automatic state-changing replays."
            );
            return true;
        }

        api.logging().logToOutput("[403 Buster] Calibrating baseline with " +
                SAFE_GET_BASELINE_REPLAYS + " live replay(s)...");

        for (int i = 0; i < SAFE_GET_BASELINE_REPLAYS; i++) {
            try {
                HttpRequestResponse replay = sendRateLimited(baseRequestResponse.request(), config.getDelayMs());
                if (replay == null) return false;

                short status = replay.response().statusCode();
                int length = replay.response().body().length();
                String body = replay.response().bodyToString();

                if (!analyzer.addBaselineSample(status, length, body)) {
                    String message = "Baseline became unstable: captured " + analyzer.getBaselineStatus()
                            + " but live replay returned " + status + ". Scan aborted.";
                    listener.onError("Baseline calibration", message);
                    api.logging().logToError("[403 Buster] " + message);
                    return false;
                }
                montoyaEvidence.addBaseline(replay.response());
            } catch (Exception e) {
                String message = "Baseline replay failed: " + e.getMessage();
                listener.onError("Baseline calibration", message);
                api.logging().logToError("[403 Buster] " + message);
                return false;
            }
        }

        api.logging().logToOutput("[403 Buster] Baseline calibrated: " +
                analyzer.getBaselineSampleCount() + " stable sample(s).");
        return true;
    }

    private HttpRequestResponse sendRateLimited(HttpRequest request, int delayMs) {
        if (!waitUntilRunnable()) return null;
        if (!enforceRateLimit(delayMs)) return null;
        if (!waitUntilRunnable()) return null;
        return api.http().sendRequest(request);
    }

    private static boolean isSafeAutomaticControlMethod(HttpRequest request) {
        String method = request.method();
        return "GET".equalsIgnoreCase(method) || "HEAD".equalsIgnoreCase(method);
    }

    private static boolean isSafeAutomaticRevalidationMethod(HttpRequest request) {
        return "GET".equalsIgnoreCase(request.method());
    }

    private boolean waitUntilRunnable() {
        while (isPaused && isRunning) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return isRunning && !Thread.currentThread().isInterrupted();
    }

    private boolean enforceRateLimit(int delayMs) {
        if (delayMs <= 0) return isRunning && !Thread.currentThread().isInterrupted();

        synchronized (rateLock) {
            if (!isRunning || Thread.currentThread().isInterrupted()) return false;

            long now = System.currentTimeMillis();
            long elapsed = now - lastRequestTimeMs;
            if (elapsed < delayMs) {
                try {
                    Thread.sleep(delayMs - elapsed);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }

            if (!isRunning || Thread.currentThread().isInterrupted()) return false;
            lastRequestTimeMs = System.currentTimeMillis();
            return true;
        }
    }
}
