package io.gaboja9.mockstock.global.websocket.service;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Set;

@Service
public class AvailableStockService {

    // TODO 주식 목록 가져오기로 추후 변경
    // 서버에서 구독하고 있는 주식 목록 (고정)
    private static final Set<String> AVAILABLE_STOCKS =
            Set.of(
                    "005930", // 삼성전자
                    "035720", // 카카오
                    "035420" // 네이버

                    // 서버에서 실제로 구독하는 주식들만 추가
                    );

    public Set<String> getAvailableStocks() {
        return AVAILABLE_STOCKS;
    }

    public boolean isStockAvailable(String stockCode) {
        return AVAILABLE_STOCKS.contains(stockCode);
    }

    // 주식명 매핑
    private static final Map<String, String> STOCK_NAMES =
            Map.of(
                    "005930", "삼성전자",
                    "035720", "카카오",
                    "035420", "네이버");

    public String getStockName(String stockCode) {
        return STOCK_NAMES.getOrDefault(stockCode, stockCode);
    }

    public Map<String, String> getAvailableStocksWithNames() {
        return STOCK_NAMES;
    }
}
