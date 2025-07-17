package io.gaboja9.mockstock.global.websocket;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.gaboja9.mockstock.global.websocket.dto.StockPrice;
import io.gaboja9.mockstock.global.websocket.mapper.StockPriceMapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Component
@Slf4j
@RequiredArgsConstructor
public class HantuWebSocketHandler extends TextWebSocketHandler {

    @Value("${hantu-openapi.appkey}")
    private String appKey;

    @Value("${hantu-openapi.appsecret}")
    private String appSecret;

    @Value("${hantu-openapi.websocket-domain:https://openapi.koreainvestment.com:9443}")
    private String websocketDomain;

    private final ObjectMapper objectMapper;
    private final RestTemplate restTemplate;
    private final WebSocketSessionManager eventService;

    private WebSocketSession session;
    private String approvalKey;
    private final ExecutorService executorService = Executors.newFixedThreadPool(5);
    private final Map<String, String> subscribedStocks = new ConcurrentHashMap<>();

    // 웹소켓 세션이 열렸을 때 호출됨

    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        this.session = session;
        eventService.setSession(session);
        log.info(
                "WebSocket connection established at {}: {}", LocalDateTime.now(), session.getId());

        // 접속 승인키 얻기
        approvalKey = getApprovalKey();

        // 초기 종목 구독
        subscribeInitialStocks();

        // 재연결시
        //        if (subscribedStocks.isEmpty()) {
        //            log.info("Initial connection. Subscribing to default stocks.");
        //            subscribeInitialStocks();
        //        } else {
        //            log.info("Reconnection detected. Restoring previous subscriptions.");
        //            resubscribeStocks();
        //        }
    }

    /** 애플리케이션 시작 시 구독할 초기 종목들을 설정합니다. */
    private void subscribeInitialStocks() {
        log.info("Subscribing to initial stocks...");
        // 삼성전자, 카카오, 네이버를 순서대로 구독 요청
        subscribeStockPrice("005930", "H1"); // 삼성전자
        subscribeStockPrice("035720", "H1"); // 카카오
        subscribeStockPrice("035420", "H1"); // 네이버
    }

    // 메세지 호출시 호출
    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message)
            throws Exception {
        String payload = message.getPayload();

        executorService.submit(() -> processMessage(payload));
    }

    // 연결 종료시 호출
    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        log.info(
                "WebSocket connection closed at {}: {}, status: {}",
                LocalDateTime.now(),
                session.getId(),
                status);
        this.session = null;
        eventService.setConnectionActive(false);
        eventService.setSession(null);
    }

    // 에러 발생시 호출
    @Override
    public void handleTransportError(WebSocketSession session, Throwable exception) {
        log.error("WebSocket transport error in session {}", session.getId(), exception);
        eventService.setConnectionActive(false);
    }

    // 웹소켓 접근키 발급
    public String getApprovalKey() {
        if (approvalKey != null) {
            return approvalKey;
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            Map<String, String> requestMap = new HashMap<>();
            requestMap.put("grant_type", "client_credentials");
            requestMap.put("appkey", appKey);
            requestMap.put("secretkey", appSecret);

            HttpEntity<Map<String, String>> entity = new HttpEntity<>(requestMap, headers);

            ResponseEntity<String> response =
                    restTemplate.exchange(
                            websocketDomain + "/oauth2/Approval",
                            HttpMethod.POST,
                            entity,
                            String.class);

            if (response.getStatusCode() == HttpStatus.OK) {
                JsonNode rootNode = objectMapper.readTree(response.getBody());
                approvalKey = rootNode.get("approval_key").asText();
                log.info("Approval key obtained: {}", approvalKey);
                return approvalKey;
            } else {
                throw new RuntimeException(
                        "Failed to obtain approval key. Status code: " + response.getStatusCode());
            }
        } catch (Exception e) {
            log.error("Error getting approval key", e);
            throw new RuntimeException("Failed to obtain approval key", e);
        }
    }

    // 실시간체결가 구독
    public void subscribeStockPrice(String stockCode, String marketCode) {
        if (session == null || !session.isOpen()) {
            log.warn("WebSocket not connected. Cannot subscribe to {}", stockCode);
            return;
        }

        try {
            Map<String, Object> header = new HashMap<>();
            header.put("approval_key", getApprovalKey());
            header.put("custtype", "P");
            header.put("tr_type", "1"); // 1: 등록
            header.put("content-type", "utf-8");

            Map<String, String> input = new HashMap<>();
            input.put("tr_id", "H0STCNT0"); // 실시간 주식 체결가
            input.put("tr_key", stockCode);

            Map<String, Object> body = new HashMap<>();
            body.put("input", input);

            Map<String, Object> request = new HashMap<>();
            request.put("header", header);
            request.put("body", body);

            String requestJson = objectMapper.writeValueAsString(request);
            session.sendMessage(new TextMessage(requestJson));
            subscribedStocks.put(stockCode, marketCode);
            log.info("Subscription request sent for stock: {}", stockCode);
        } catch (Exception e) {
            log.error("Error subscribing to stock price for code: {}", stockCode, e);
        }
    }

    /** 실시간 시세 구독 해제 */
    public void unsubscribeStockPrice(String stockCode, String marketCode) {
        if (session == null || !session.isOpen()) {
            log.warn("WebSocket not connected. Cannot unsubscribe.");
            return;
        }

        try {
            Map<String, Object> header = new HashMap<>();
            header.put("approval_key", getApprovalKey());
            header.put("custtype", "P");
            header.put("tr_type", "2"); // 2: 해제
            header.put("content-type", "utf-8");

            Map<String, String> input = new HashMap<>();
            input.put("tr_id", "H0STCNT0");
            input.put("tr_key", stockCode);

            Map<String, Object> body = new HashMap<>();
            body.put("input", input);

            Map<String, Object> request = new HashMap<>();
            request.put("header", header);
            request.put("body", body);

            String requestJson = objectMapper.writeValueAsString(request);
            session.sendMessage(new TextMessage(requestJson));
            subscribedStocks.remove(stockCode);
            log.info("Unsubscribed from real-time price for stock: {}", stockCode);
        } catch (Exception e) {
            log.error("Error unsubscribing from stock price for code: {}", stockCode, e);
        }
    }

    // 메세지 처리
    private void processMessage(String message) {
        if (message.startsWith("0|H0STCNT0|")) {
            try {
                String[] parts = message.split("\\|");
                if (parts.length >= 4) {
                    String[] fields = parts[3].split("\\^");
                    StockPrice priceData = StockPriceMapper.parseStockPriceData(fields);
                    log.info(priceData.toString());
                }
            } catch (Exception e) {
                log.error("Error processing real-time data: {}", message, e);
            }
            return;
        }

        try {
            JsonNode rootNode = objectMapper.readTree(message);
            if (rootNode.has("header")) {
                JsonNode header = rootNode.get("header");
                String trId = header.has("tr_id") ? header.get("tr_id").asText() : "";
                // pingpong이 왔을때 그대로 보내준다.
                if ("PINGPONG".equals(trId)) {
                    log.debug("PINGPONG check received from server. Sending response.");
                    // 받은 메시지를 그대로 다시 보내주는 것이 가장 간단하고 확실한 응답 방식
                    session.sendMessage(new TextMessage(message));
                    return; // 응답 후 처리 종료
                }

                // 기타 응답 메시지 처리 (구독 성공/실패 등)
                if (rootNode.has("body")) {
                    JsonNode body = rootNode.get("body");
                    if (body.has("msg_cd")) {
                        log.info(
                                "Response received: [{}], {}",
                                body.get("msg_cd").asText(),
                                body.get("msg1").asText());
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Could not parse JSON message: {}", message, e);
        }
    }

    //  /**
    //   * 재연결 후 기존 구독 복원
    //   */
    //  private void resubscribeStocks() {
    //    if (subscribedStocks.isEmpty()) {
    //      return;
    //    }
    //
    //    log.info("Resubscribing to {} stocks after reconnection", subscribedStocks.size());
    //    new HashMap<>(subscribedStocks).forEach((stockCode, marketCode) -> {
    //      try {
    //        Thread.sleep(100);
    //        subscribeStockPrice(stockCode, marketCode);
    //      } catch (InterruptedException e) {
    //        Thread.currentThread().interrupt();
    //        log.error("Resubscription interrupted", e);
    //      }
    //    });
    //  }

}
