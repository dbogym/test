package io.gaboja9.mockstock.global.websocket.controller;

import io.gaboja9.mockstock.global.websocket.service.AvailableStockService;

import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class AvailableStockController {

    // TODO 주식 목록 가져오기로 변경예정
    private final AvailableStockService availableStockService;

    @GetMapping("/stocks/available")
    public ResponseEntity<Map<String, Object>> getAvailableStocks() {
        return ResponseEntity.ok(
                Map.of("stocks", availableStockService.getAvailableStocksWithNames()));
    }
}
