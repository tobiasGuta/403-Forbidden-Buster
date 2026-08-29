package com.bughunter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Manages attack execution with thread pool, pause/resume/stop controls,
 * global rate limiting, v8 response analysis, and progress reporting.
 */
public class AttackEngine {

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

    // Global rate limiter — shared across all threads
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

    /**
     * Launch a full bypass attack against the given request.
     */
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
        // Build baseline for comparison from the exact Burp request/response context.
        short baseStatus = baseRequestResponse.response().statusCode();
        int baseLength = baseRequestResponse.response().body().length();
        String baseBody = baseRequestResponse.response().bodyToString();
        String baseMethod = baseRequestResponse.request().method();
        ResponseAnalyzer analyzer = new ResponseAnalyzer(baseStatus, baseLength, baseBody, baseMethod);

        // Generate all payloads
        List<PayloadGenerator.Payload> payloads = PayloadGenerator.generate(baseRequestResponse, config);
        int total = payloads.size();

        api.logging().logToOutput("[403 Buster] Starting attack with " + total + " payloads | " +
                config.getThreadCount() + " threads | " + config.getDelayMs() + "ms delay");

        listener.onAttackStarted(total);

        // Create thread pool
        executor = Executors.newFixedThreadPool(config.getThreadCount(), r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });

        AtomicInteger completed = new AtomicInteger(0);

        for (PayloadGenerator.Payload payload : payloads) {
            if (!isRunning) break;

            // Avoid filling the queue while paused. Workers also enforce pause immediately before sending.
            if (!waitUntilRunnable()) break;

            executor.submit(() -> {
                try {
                    if (!waitUntilRunnable()) return;

                    // Global rate limiting. If Stop interrupts the wait, do not send afterward.
                    if (!enforceRateLimit(config.getDelayMs())) return;
                    if (!waitUntilRunnable()) return;

                    HttpRequestResponse response = api.http().sendRequest(payload.request);
                    short statusCode = response.response().statusCode();
                    int length = response.response().body().length();
                    String body = response.response().bodyToString();

                    ResponseAnalyzer.Analysis analysis = analyzer.analyze(
                            payload.request.method(),
                            statusCode,
                            length,
                            body,
                            config.isHide404(),
                            config.isHide403()
                    );

                    if (analysis.shouldLog()) {
                        BypassResult result = new BypassResult(
                                idCounter.getAndIncrement(),
                                payload.request.method(),
                                payload.request.url(),
                                payload.description,
                                payload.category,
                                statusCode,
                                length,
                                response,
                                analysis.type(),
                                analysis.confidence(),
                                analysis.bodySimilarity(),
                                analysis.rationale()
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

        // Wait for all tasks to finish
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

    /**
     * Blocks a worker while paused and returns false if the run has been stopped or interrupted.
     */
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

    /**
     * Enforces global rate limiting across all threads.
     * Returns false when interrupted so Stop is a hard send barrier.
     */
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
