package io.gaboja9.mockstock.global.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;

import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info =
                @Info(
                        title = "MockStock API",
                        description =
                                """
                                ## MockStock API Documentation

                                ### 인증
                                - **JWT Bearer Token** 사용
                                - 우측 상단 "Authorize" 버튼을 클릭하여 토큰 입력
                                - 토큰 형식: `Bearer {your_jwt_token}`

                                ### REST API
                                일반적인 HTTP 요청/응답 기반 API

                                ### WebSocket API

                                **엔드포인트:** `/ws-stock`
                                **프로토콜:** STOMP over WebSocket (SockJS 지원)
                                **인증:** 익명 사용자 허용 (세션 기반)

                                **구독 가능한 토픽:**
                                - `/topic/stock/{stockCode}` - 실시간 주식 가격 (유효한 종목코드만)
                                - `/user/queue/errors` - 에러 메시지 수신 (필수)

                                **에러 코드:**
                                - `INVALID_STOCK` - 존재하지 않는 종목코드 (400)
                                - `SOCKET_ERROR` - 소켓 연결 오류 (연결 종료됨)
                                - `INTERNAL_ERROR` - 서버 내부 오류 (500, 연결 종료됨)

                                **연결 및 구독 예시:**
                                ```javascript
                                const socket = new SockJS('/ws-stock');
                                const stompClient = Stomp.over(socket);

                                stompClient.connect({}, function(frame) {
                                    console.log('WebSocket 연결 성공');

                                    // 에러 핸들링 구독 (필수)
                                    stompClient.subscribe('/user/queue/errors', function(message) {
                                        const error = JSON.parse(message.body);
                                        console.error('WebSocket 오류:', error.code, error.message);
                                    });

                                    // 삼성전자 주식 가격 구독
                                    stompClient.subscribe('/topic/stock/005930', function(message) {
                                        const stockData = JSON.parse(message.body);
                                        console.log('삼성전자 실시간 데이터:', stockData);
                                    });
                                });
                                ```

                                **주의사항:**
                                - 현재는 주식 데이터 구독만 지원
                                - 잘못된 종목코드 구독 시 에러 메시지 후 해당 구독 차단
                                - 심각한 오류 발생 시 자동 연결 종료
                                - 모든 에러는 `/user/queue/errors`로 수신
                                """),
        security = @SecurityRequirement(name = "bearerAuth"))
@SecurityScheme(
        name = "bearerAuth",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT",
        description = "JWT 토큰을 입력하세요. 'Bearer ' 접두사는 자동으로 추가됩니다.")
public class SwaggerConfig {}
