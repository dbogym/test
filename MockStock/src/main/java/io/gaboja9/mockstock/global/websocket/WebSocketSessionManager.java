package io.gaboja9.mockstock.global.websocket;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import org.springframework.stereotype.Component;
import org.springframework.web.socket.WebSocketSession;

@Component
@Slf4j
public class WebSocketSessionManager {

    @Getter private WebSocketSession session;
    private boolean connectionActive = false;

    // 세션설정
    public void setSession(WebSocketSession session) {
        this.session = session;
        this.connectionActive = (session != null && session.isOpen());
        //        log.info(
        //                "WebSocket session set: {}, active: {}",
        //                session != null ? session.getId() : "null",
        //                connectionActive);
    }

    // 연결 상태 설정
    public void setConnectionActive(boolean active) {
        this.connectionActive = active;
        log.info("WebSocket connection active state changed to: {}", active);
    }

    // 연결 상태 반환
    public boolean isConnectionActive() {
        return connectionActive;
    }
}
