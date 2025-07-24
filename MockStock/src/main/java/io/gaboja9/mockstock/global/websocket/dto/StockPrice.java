package io.gaboja9.mockstock.global.websocket.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "실시간 주식 체결 데이터 DTO")
public class StockPrice {

    @Schema(description = "종목 코드", example = "005930")
    private String stockCode; // 종목코드

    @Schema(description = "현재가", example = "91500")
    private int currentPrice; // 현재가

    @Schema(description = "전일 대비 등락률 (%)", example = "1.23")
    private double dayOverDayPercent; // 전일 대비 등락률

    @Schema(description = "체결 시간 (HHmmss)", example = "093015")
    private String tradeTime; // 체결 시간 (HHmmss 형식)

    @Schema(description = "체결 거래량", example = "100")
    private long tradeVolume; // 체결 거래량 (CNTG_VOL)

    @Schema(description = "고가", example = "92000")
    private int highPrice; // 고가

    @Schema(description = "저가", example = "89000")
    private int lowPrice; // 저가

    @Schema(description = "누적 거래량", example = "32345912")
    private long cumulativeVolume; // 누적 거래량

    @Override
    public String toString() {
        return String.format(
                "종목코드: %s | 현재가: %,d원 | 등락률: %.2f%% | 시간: %s | 체결 거래량: %,d | 고가: %,d | 저가: %,d | 누적"
                        + " 거래량: %,d",
                stockCode,
                currentPrice,
                dayOverDayPercent,
                formatTime(tradeTime),
                tradeVolume,
                highPrice,
                lowPrice,
                cumulativeVolume);
    }

    private String formatTime(String timeStr) {
        if (timeStr == null || timeStr.length() != 6) {
            return "N/A";
        }
        return timeStr.substring(0, 2)
                + ":"
                + timeStr.substring(2, 4)
                + ":"
                + timeStr.substring(4, 6);
    }
}
