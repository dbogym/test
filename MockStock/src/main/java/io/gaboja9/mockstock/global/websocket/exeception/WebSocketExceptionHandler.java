package io.gaboja9.mockstock.global.websocket.exeception;

import io.gaboja9.mockstock.global.exception.ErrorCode;
import io.gaboja9.mockstock.global.exception.ErrorResponse;
import io.gaboja9.mockstock.global.websocket.WebSocketSessionManager;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.messaging.Message;
import org.springframework.messaging.handler.annotation.MessageExceptionHandler;
import org.springframework.messaging.simp.annotation.SendToUser;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.socket.messaging.StompSubProtocolErrorHandler;

import java.net.SocketException;

@ControllerAdvice
@RequiredArgsConstructor
@Slf4j
public class WebSocketExceptionHandler extends StompSubProtocolErrorHandler {

    private final WebSocketSessionManager sessionManager;

    // @SendToUser 사용
    @MessageExceptionHandler(SocketException.class)
    @SendToUser("/queue/errors")
    public ErrorResponse handleSocketException(Message<?> message) {
        StompHeaderAccessor accessor = StompHeaderAccessor.wrap(message);
        String sessionId = accessor.getSessionId();

        log.error("Critical socket error from session: {}", sessionId);

        // 시스템 에러는 연결 종료
        sessionManager.disconnectSession(sessionId);

        return ErrorResponse.of(
                ErrorCode.SOCKET_ERROR.getCode(),
                "시스템 오류가 발생했습니다. 다시 연결해주세요.",
                ErrorCode.SOCKET_ERROR.getStatus().value());
    }

    // 서버 내부 오류
    @MessageExceptionHandler(RuntimeException.class)
    @SendToUser("/queue/errors")
    public ErrorResponse handleRuntimeException(Message<?> message, RuntimeException ex) {
        StompHeaderAccessor accessor = StompHeaderAccessor.wrap(message);
        String sessionId = accessor.getSessionId();

        log.error("Unexpected runtime error from session: {}", sessionId, ex);

        sessionManager.disconnectSession(sessionId);

        return ErrorResponse.of("INTERNAL_ERROR", "서버 내부 오류가 발생했습니다.", 500);
    }
}
