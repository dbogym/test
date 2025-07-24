package io.gaboja9.mockstock.global.websocket;

import lombok.extern.slf4j.Slf4j;

import org.springframework.web.socket.client.WebSocketClient;
import org.springframework.web.socket.client.WebSocketConnectionManager;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

@Slf4j
public class HantuWebSocketConnectionManager extends WebSocketConnectionManager {

    private final ScheduledExecutorService scheduler;
    private ScheduledFuture<?> heartbeatTask;
    private final HantuWebSocketSessionManager sessionManager;
    private final HantuWebSocketHandler webSocketHandler;

    private volatile boolean running = false;

    public HantuWebSocketConnectionManager(
            WebSocketClient client,
            HantuWebSocketHandler webSocketHandler,
            String uriTemplate,
            HantuWebSocketSessionManager sessionManager) {
        super(client, webSocketHandler, uriTemplate);
        this.scheduler = new ScheduledThreadPoolExecutor(1);
        this.sessionManager = sessionManager;
        this.webSocketHandler = webSocketHandler;
    }

    public void startConnection() {
        //        log.info("Starting WebSocket connection manager");
        this.running = true;
        super.start();
        startHeartbeat();
    }

    public void stopConnection() {
        //        log.info("Stopping WebSocket connection manager");
        this.running = false;
        stopHeartbeat();
        super.stop();
    }

    private void startHeartbeat() {
        stopHeartbeat();
        heartbeatTask =
                scheduler.scheduleAtFixedRate(
                        () -> {
                            //  연결 상태 체크하여 재연결을 시도합니다.
                            if (this.running
                                    && (sessionManager.getSession() == null
                                            || !sessionManager.getSession().isOpen())) {
                                //                                log.warn(
                                //                                        "Heartbeat detected
                                // inactive session. Attempting to"
                                //                                                + "
                                // reconnect...");
                                reconnect();
                            }
                        },
                        30,
                        30,
                        TimeUnit.SECONDS);
        //        log.info("WebSocket heartbeat started");
    }

    private void stopHeartbeat() {
        if (heartbeatTask != null && !heartbeatTask.isCancelled()) {
            heartbeatTask.cancel(false);
            //            log.info("WebSocket heartbeat stopped");
        }
    }

    private void reconnect() {
        //        log.info("Attempting to reconnect WebSocket");
        super.stop();
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return;
        }
        super.start();
    }
}
