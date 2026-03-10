package com.bughunter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Manages attack execution with thread pool, pause/resume/stop controls,
 * proper rate limiting, and progress reporting.
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
        // Build baseline for comparison
        short baseStatus = baseRequestResponse.response().statusCode();
        int baseLength = baseRequestResponse.response().body().length();
        ResponseAnalyzer analyzer = new ResponseAnalyzer(baseStatus, baseLength);

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

            // Pause support
            while (isPaused && isRunning) {
                try { Thread.sleep(200); }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
            }
            if (!isRunning) break;

            executor.submit(() -> {
                try {
                    // Global rate limiting
                    enforceRateLimit(config.getDelayMs());

                    HttpRequestResponse response = api.http().sendRequest(payload.request);
                    short statusCode = response.response().statusCode();
                    int length = response.response().body().length();

                    if (analyzer.shouldLog(statusCode, length, config.isHide404(), config.isHide403())) {
                        boolean interesting = analyzer.classify(statusCode, length) == ResponseAnalyzer.ResultType.BYPASS
                                || analyzer.classify(statusCode, length) == ResponseAnalyzer.ResultType.REDIRECT;

                        BypassResult result = new BypassResult(
                                idCounter.getAndIncrement(),
                                payload.request.method(),
                                payload.request.url(),
                                payload.description,
                                payload.category,
                                statusCode,
                                length,
                                response,
                                interesting
                        );
                        listener.onResult(result);
                    }
                } catch (Exception e) {
                    listener.onError(payload.description, e.getMessage());
                    api.logging().logToError("[403 Buster] Error: " + payload.description + " — " + e.getMessage());
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
     * Enforces global rate limiting across all threads.
     * This ensures the actual request rate matches user expectation.
     */
    private void enforceRateLimit(int delayMs) {
        if (delayMs <= 0) return;
        synchronized (rateLock) {
            long now = System.currentTimeMillis();
            long elapsed = now - lastRequestTimeMs;
            if (elapsed < delayMs) {
                try { Thread.sleep(delayMs - elapsed); }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            }
            lastRequestTimeMs = System.currentTimeMillis();
        }
    }
}
