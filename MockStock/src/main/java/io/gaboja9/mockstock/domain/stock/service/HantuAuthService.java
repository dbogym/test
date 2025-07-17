package io.gaboja9.mockstock.domain.stock.service;

import io.gaboja9.mockstock.domain.stock.dto.HantuTokenResponse;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
@Slf4j
@RequiredArgsConstructor
public class HantuAuthService {

    private final RestTemplate restTemplate;

    @Value("${hantu-openapi.domain}")
    private String apiDomain;

    @Value("${hantu-openapi.appkey}")
    private String appKey;

    @Value("${hantu-openapi.appsecret}")
    private String appSecret;

    // volatile 키워드는 멀티스레드 환경에서 가시성을 보장하여,
    // 한 스레드에서 변경된 값을 다른 스레드가 즉시 볼 수 있게 합니다.
    private volatile String cachedAccessToken;
    private volatile long tokenExpirationTime;

    public String getValidAccessToken() {
        // 첫 번째 검사 (Lock 없이)
        if (isTokenValid()) {
            return cachedAccessToken;
        }

        // 토큰 갱신이 필요한 경우에만 진입하여 비용을 최소화합니다.
        synchronized (this) {
            // 두 번째 검사 (Lock 상태에서)
            // 다른 스레드가 이미 토큰을 갱신했을 수 있으므로 다시 한번 확인합니다.
            if (isTokenValid()) {
                return cachedAccessToken;
            }

            log.info("액세스 토큰이 없거나 만료되어 새로 발급합니다.");
            // 새 토큰을 발급하고 그 결과를 바탕으로 토큰을 반환합니다.
            if (fetchNewAccessToken()) {
                return this.cachedAccessToken;
            } else {
                return null; // 토큰 발급 최종 실패
            }
        }
    }

    private boolean isTokenValid() {
        return cachedAccessToken != null
                && System.currentTimeMillis() < tokenExpirationTime - 60000;
    }

    private boolean fetchNewAccessToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        String requestBody =
                String.format(
                        "{\"grant_type\":\"client_credentials\",\"appkey\":\"%s\",\"appsecret\":\"%s\"}",
                        appKey, appSecret);
        HttpEntity<String> entity = new HttpEntity<>(requestBody, headers);

        try {
            ResponseEntity<HantuTokenResponse> response =
                    restTemplate.exchange(
                            apiDomain + "/oauth2/tokenP",
                            HttpMethod.POST,
                            entity,
                            HantuTokenResponse.class); // JSON 응답을 DTO로 자동 변환

            HantuTokenResponse tokenResponse = response.getBody();

            if (tokenResponse != null && tokenResponse.getAccessToken() != null) {
                // DTO의 getter를 사용하여 안전하게 데이터에 접근
                this.cachedAccessToken = tokenResponse.getAccessToken();
                long expiresInMillis = (long) tokenResponse.getExpiresIn() * 1000;
                this.tokenExpirationTime = System.currentTimeMillis() + expiresInMillis;
                log.info("새로운 액세스 토큰 발급 완료. 만료까지 남은 시간: {}초", tokenResponse.getExpiresIn());
                return true;
            } else {
                log.error("액세스 토큰 응답 파싱 실패. 응답: {}", response.getBody());
                return false;
            }
        } catch (Exception e) {
            log.error("Access Token 발급 요청 실패", e);
            // 실패 시 기존 토큰 정보 초기화
            this.cachedAccessToken = null;
            this.tokenExpirationTime = 0;
            return false;
        }
    }
}
