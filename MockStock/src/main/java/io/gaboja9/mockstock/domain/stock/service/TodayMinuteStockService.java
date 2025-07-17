package io.gaboja9.mockstock.domain.stock.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.influxdb.client.InfluxDBClient;
import com.influxdb.client.WriteApi;
import com.influxdb.client.domain.WritePrecision;

import io.gaboja9.mockstock.domain.stock.measurement.MinuteStockPrice;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Service
@Slf4j
public class TodayMinuteStockService {

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final HantuAuthService hantuAuthService;
    private final InfluxDBClient minuteClient;

    @Value("${hantu-openapi.domain}")
    private String apiDomain;

    @Value("${hantu-openapi.appkey}")
    private String appKey;

    @Value("${hantu-openapi.appsecret}")
    private String appSecret;

    public TodayMinuteStockService(
            RestTemplate restTemplate,
            ObjectMapper objectMapper,
            HantuAuthService hantuAuthService,
            @Qualifier("minuteInfluxDBClient") InfluxDBClient minuteClient) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
        this.hantuAuthService = hantuAuthService;
        this.minuteClient = minuteClient;
    }

    // 단일 종목의 '당일' 분봉 데이터를 가져와 InfluxDB에 저장합니다.

    public void fetchAndSaveCurrentDayMinuteData(
            String marketCode,
            String stockCode,
            String startTime,
            String periodCode,
            String ClsCode) {
        log.info(
                "당일 분봉 데이터 수집 시작 - 시장: {}, 종목: {}, 시작시간: {}, 기간분류: {}, 체결분류: {}",
                marketCode,
                stockCode,
                startTime,
                periodCode,
                ClsCode);

        String accessToken = hantuAuthService.getValidAccessToken();
        if (accessToken == null) {
            log.error("접근 토큰 발급 실패 - 데이터 수집 중단 (종목: {})", stockCode);
            return;
        }

        String responseBody =
                getCurrentDayStockMinuteData(
                        marketCode, stockCode, startTime, periodCode, ClsCode, accessToken);

        if (responseBody != null) {
            saveMinuteStockDataToInflux(responseBody, stockCode);
        }

        log.info("당일 분봉 데이터 수집 완료 - {}", stockCode);
    }

    private String getCurrentDayStockMinuteData(
            String marketCode,
            String stockCode,
            String startTime,
            String periodCode,
            String clsCode,
            String accessToken) {

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.set("authorization", "Bearer " + accessToken);
        headers.set("appkey", appKey);
        headers.set("appsecret", appSecret);
        headers.set("tr_id", "FHKST03010200");
        headers.set("custtype", "P");

        UriComponentsBuilder builder =
                UriComponentsBuilder.fromHttpUrl(
                                apiDomain
                                        + "/uapi/domestic-stock/v1/quotations/inquire-time-itemchartprice")
                        .queryParam("FID_COND_MRKT_DIV_CODE", marketCode)
                        .queryParam("FID_INPUT_ISCD", stockCode)
                        .queryParam("FID_INPUT_HOUR_1", startTime) // 시작 시간
                        .queryParam("FID_PW_DATA_INCU_YN", periodCode)
                        .queryParam("FID_ETC_CLS_CODE", clsCode);

        HttpEntity<?> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<String> response =
                    restTemplate.exchange(
                            builder.toUriString(), HttpMethod.GET, entity, String.class);
            return response.getBody();
        } catch (Exception e) {
            log.error("당일 분봉 데이터 API 요청 실패 - 종목: {}, URL: {}", stockCode, builder.toUriString(), e);
            return null;
        }
    }

    // 분봉 데이터 저장 로직
    private void saveMinuteStockDataToInflux(String responseBody, String stockCode) {
        try {
            log.info("API 응답 원본 (종목코드: {}): {}", stockCode, responseBody);

            JsonNode rootNode = objectMapper.readTree(responseBody);
            JsonNode output2 = rootNode.path("output2");

            if (output2.isMissingNode() || !output2.isArray()) {
                log.warn("{} 종목에 대한 분봉 데이터 없음. 응답: {}", stockCode, responseBody);
                return;
            }

            List<MinuteStockPrice> pricePoints = new ArrayList<>();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");
            ZoneId koreaZone = ZoneId.of("Asia/Seoul");

            for (JsonNode node : output2) {
                MinuteStockPrice point = new MinuteStockPrice();

                String dateStr = node.path("stck_bsop_date").asText();
                String timeStr = node.path("stck_cntg_hour").asText();
                LocalDateTime dateTime = LocalDateTime.parse(dateStr + timeStr, formatter);

                ZonedDateTime zonedDateTime = dateTime.atZone(koreaZone);
                point.setTimestamp(zonedDateTime.toInstant());

                point.setStockCode(stockCode);
                point.setOpenPrice(Long.parseLong(node.path("stck_oprc").asText()));
                point.setMaxPrice(Long.parseLong(node.path("stck_hgpr").asText()));
                point.setMinPrice(Long.parseLong(node.path("stck_lwpr").asText()));
                point.setClosePrice(Long.parseLong(node.path("stck_prpr").asText()));
                point.setAccumTrans(Long.parseLong(node.path("cntg_vol").asText()));

                pricePoints.add(point);
            }

            if (!pricePoints.isEmpty()) {
                try (WriteApi writeApi = minuteClient.getWriteApi()) {
                    writeApi.writeMeasurements(WritePrecision.NS, pricePoints);
                    log.info("{} 종목의 분봉 데이터 {}건 저장 완료", stockCode, pricePoints.size());
                }
            }
        } catch (Exception e) {
            log.error("{} 종목 분봉 데이터 파싱 또는 InfluxDB 저장 중 에러 발생", stockCode, e);
        }
    }
}
