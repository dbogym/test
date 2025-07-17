package io.gaboja9.mockstock.global.websocket.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class StockPrice {

    private String stockCode; // 종목코드
    private int currentPrice; // 현재가
    private double dayOverDayPercent; // 전일 대비 등락률
    private String tradeTime; // 체결 시간 (HHmmss 형식)
    private long tradeVolume; // 체결 거래량 (CNTG_VOL)

    @Override
    public String toString() {
        return String.format(
                "종목코드: %s | 현재가: %,d원 | 등락률: %.2f%% | 시간: %s | 체결 거래량 : %d",
                stockCode, currentPrice, dayOverDayPercent, formatTime(tradeTime), tradeVolume);
    }

    private String formatTime(String timeStr) {
        if (timeStr == null || timeStr.length() != 6) return "N/A";
        return timeStr.substring(0, 2)
                + ":"
                + timeStr.substring(2, 4)
                + ":"
                + timeStr.substring(4, 6);
    }
}
