package io.gaboja9.mockstock.global.websocket;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.client.WebSocketClient;
import org.springframework.web.socket.client.standard.StandardWebSocketClient;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

@Configuration
@EnableWebSocket
public class HantuWebSocketConfig implements WebSocketConfigurer {

    @Value("${hantu-openapi.websocket-uri:ws://ops.koreainvestment.com:31000}")
    private String websocketUri;

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {}

    @Bean
    public WebSocketClient webSocketClient() {
        StandardWebSocketClient client = new StandardWebSocketClient();

        // 메세지가 버퍼보다 커 웹소켓이 종료되는 문제가 존재하여 버퍼의 크기르 설정하였습니다.
        client.getUserProperties()
                .put("org.apache.tomcat.websocket.textBufferSize", 5 * 1024 * 1024);
        client.getUserProperties()
                .put("org.apache.tomcat.websocket.binaryBufferSize", 5 * 1024 * 1024);
        // 타임아웃 설정 (60초)
        client.getUserProperties().put("org.apache.tomcat.websocket.IO_TIMEOUT_MS", "60000");
        return client;
    }

    @Bean
    public HantuWebSocketConnectionManager HantuWebSocketConnectionManager(
            WebSocketClient webSocketClient,
            HantuWebSocketHandler handler,
            HantuWebSocketSessionManager webSocketEventService) {

        HantuWebSocketConnectionManager connectionManager =
                new HantuWebSocketConnectionManager(
                        webSocketClient, handler, websocketUri, webSocketEventService);
        // 자동 시작을 비활성화하고, ApplicationReadyEvent를 통해 명시적으로 시작합니다.
        connectionManager.setAutoStartup(false);
        return connectionManager;
    }

    // 스프링 부트 애플리케이션이 완전히 준비된 후에 웹소켓 연결을 시작합니다. 이 방법을 사용하면 모든 Bean이 초기화된 후에 연결을 시도하므로 더 안정적입니다.
    @Bean
    public ApplicationListener<ApplicationReadyEvent> webSocketConnectionStarter(
            HantuWebSocketConnectionManager connectionManager) {
        return event -> connectionManager.startConnection();
    }
}
