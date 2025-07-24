package io.gaboja9.mockstock.global.websocket;

import io.gaboja9.mockstock.global.exception.ErrorResponse;
import io.gaboja9.mockstock.global.websocket.service.AvailableStockService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Slf4j
@Component
public class StockSubscriptionInterceptor implements ChannelInterceptor {

    private final AvailableStockService availableStockService;
    private final ObjectProvider<SimpMessagingTemplate> messagingTemplateProvider;

    @Override
    public Message<?> preSend(Message<?> message, MessageChannel channel) {
        StompHeaderAccessor accessor = StompHeaderAccessor.wrap(message);

        if (StompCommand.SUBSCRIBE.equals(accessor.getCommand())) {
            String destination = accessor.getDestination();
            String sessionId = accessor.getSessionId();

            if (destination != null && destination.startsWith("/topic/stock/")) {
                String stockCode = destination.substring("/topic/stock/".length());

                if (!availableStockService.isStockAvailable(stockCode)) {
                    log.warn("잘못된 종목코드 구독 시도: {} (session: {})", stockCode, sessionId);

                    String user =
                            accessor.getUser() != null ? accessor.getUser().getName() : sessionId;

                    //  지연 주입으로 해결
                    messagingTemplateProvider
                            .getObject()
                            .convertAndSendToUser(
                                    user,
                                    "/queue/errors",
                                    ErrorResponse.of(
                                            "INVALID_STOCK",
                                            "종목코드 '" + stockCode + "'는 존재하지 않습니다.",
                                            400));

                    return null;
                }

                log.info("✅ 유효한 종목 구독: {} (session: {})", stockCode, sessionId);
            }
        }

        return message;
    }
}
