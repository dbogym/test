package io.gaboja9.mockstock.global.websocket;

import lombok.extern.slf4j.Slf4j;

import org.springframework.stereotype.Service;
import org.springframework.web.socket.WebSocketSession;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
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

    // 연결이 이미 닫힌 후 호출되는 cleanup 메서드
    public void removeSession(String sessionId) {
        WebSocketSession session = sessions.remove(sessionId);
        if (session != null) {
            log.info("Session removed from registry: {}", sessionId);
        }
    }

    // 능동적으로 연결을 끊을 때 사용하는 메서드
    public void disconnectSession(String sessionId) {
        WebSocketSession session = sessions.remove(sessionId);
        if (session != null) {
            log.info("Session removed: {}", sessionId);
            try {
                session.close();
            } catch (IOException e) {
                log.warn("Failed to close WebSocket session: {}", sessionId, e);
            }
        }
    }
}
