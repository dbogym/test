package io.gaboja9.mockstock.global.config;

import lombok.extern.slf4j.Slf4j;

import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.MessageHeaderAccessor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collections;

@Component
@Slf4j
public class JwtChannelInterceptor implements ChannelInterceptor {

    @Override
    public Message<?> preSend(Message<?> message, MessageChannel channel) {
        StompHeaderAccessor accessor =
                MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);

        if (StompCommand.CONNECT.equals(accessor.getCommand())) {
            String sessionId = accessor.getSessionId();

            // Spring Security의 AnonymousAuthenticationToken 사용
            AnonymousAuthenticationToken anonymousAuth =
                    new AnonymousAuthenticationToken(
                            "anonymousUser",
                            "user_" + sessionId,
                            Collections.singletonList(
                                    new SimpleGrantedAuthority("ROLE_ANONYMOUS")));

            accessor.setUser(anonymousAuth);
            log.info("WebSocket 연결: 세션={}, 익명 사용자 설정됨", sessionId);
        }

        return message;
    }
}
