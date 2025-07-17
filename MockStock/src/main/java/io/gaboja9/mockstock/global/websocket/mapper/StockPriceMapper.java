package io.gaboja9.mockstock.global.websocket.mapper;

import io.gaboja9.mockstock.global.websocket.dto.StockPrice;

public class StockPriceMapper {

    // 문자열 배열 데이터를 StockPriceData로 파싱
    public static StockPrice parseStockPriceData(String[] fields) {
        return StockPrice.builder()
                .stockCode(fields[0])
                .tradeTime(fields[1])
                .currentPrice(parseInt(fields[2]))
                .dayOverDayPercent(parseDouble(fields[5]))
                .tradeVolume(parseLong(fields[12]))
                .build();
    }

    private static int parseInt(String value) {
        try {
            return Integer.parseInt(value);
        } catch (Exception e) {
            return 0;
        }
    }

    public static long parseLong(String value) {
        try {
            return Long.parseLong(value);
        } catch (Exception e) {
            return 0;
        }
    }

    private static double parseDouble(String value) {
        try {
            return Double.parseDouble(value);
        } catch (Exception e) {
            return 0.0;
        }
    }
}
