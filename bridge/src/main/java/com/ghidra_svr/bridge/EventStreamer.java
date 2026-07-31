package com.ghidra_svr.bridge;

import ghidra.framework.remote.RepositoryChangeEvent;
import ghidra.framework.remote.RepositoryHandle;

import java.util.function.BiConsumer;

/**
 * Background thread that calls {@link RepositoryHandle#getEvents()}, which
 * blocks until the Ghidra server has events to deliver.
 *
 * When an event arrives the provided callback is invoked on this thread,
 * so the callback must be thread-safe (BridgeConnection.writeLine is
 * synchronized for exactly this reason).
 *
 * Stopping: call {@link #stop()}.  The thread will exit after the current
 * blocking RMI call returns or throws — there is no way to interrupt a
 * blocking RMI call directly, but closing the underlying RepositoryHandle
 * (done by GhidraSession.closeRepo / disconnect) will cause getEvents() to
 * throw and wake the thread.
 */
public class EventStreamer implements Runnable {

    private final String repoName;
    private final RepositoryHandle repo;
    private final BiConsumer<String, RepositoryChangeEvent> onEvent;

    private volatile boolean running = false;
    private volatile Thread thread;

    public EventStreamer(String repoName, RepositoryHandle repo,
            BiConsumer<String, RepositoryChangeEvent> onEvent) {
        this.repoName = repoName;
        this.repo     = repo;
        this.onEvent  = onEvent;
    }

    public void start() {
        running = true;
        thread  = new Thread(this, "event-streamer/" + repoName);
        thread.setDaemon(true);
        thread.start();
    }

    public void stop() {
        running = false;
        Thread t = thread;
        if (t != null) {
            t.interrupt();
        }
    }

    @Override
    public void run() {
        System.err.println("[ghidra-bridge] event stream started for " + repoName);
        try {
            while (running) {
                RepositoryChangeEvent[] events = repo.getEvents(); // blocks
                for (RepositoryChangeEvent evt : events) {
                    if (!running) return;
                    if (evt.type == RepositoryChangeEvent.REP_NULL_EVENT) continue; // keepalive
                    onEvent.accept(repoName, evt);
                }
            }
        } catch (java.io.InterruptedIOException e) {
            // Normal stop path — interrupted while blocked in RMI.
        } catch (Exception e) {
            if (running) {
                System.err.println("[ghidra-bridge] event stream error for " + repoName
                        + ": " + e.getMessage());
            }
        } finally {
            running = false;
            System.err.println("[ghidra-bridge] event stream stopped for " + repoName);
        }
    }
}
