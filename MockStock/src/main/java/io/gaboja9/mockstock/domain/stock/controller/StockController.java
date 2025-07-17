package io.gaboja9.mockstock.domain.stock.controller;

import io.gaboja9.mockstock.domain.stock.service.DailyStockService;
import io.gaboja9.mockstock.domain.stock.service.MinuteStockService;
import io.gaboja9.mockstock.domain.stock.service.TodayMinuteStockService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** 주식 데이터 수집을 위한 컨트롤러 */
@Slf4j
@RestController
@RequestMapping("/api/stocks")
@RequiredArgsConstructor
public class StockController {

    private final DailyStockService stockService;
    private final MinuteStockService minuteStockService;
    private final TodayMinuteStockService todayMinuteStockService;

    @GetMapping("/fetch-data")
    public ResponseEntity<?> fetchStockData(
            @RequestParam String marketCode, //  주식 J
            @RequestParam String stockCode, //  단일 종목 코드
            @RequestParam String startDate,
            @RequestParam String endDate,
            @RequestParam String periodCode) {

        log.info("주식 데이터 수집 요청: {}, 기간: {} ~ {}", stockCode, startDate, endDate);

        // 단일 종목 처리용 서비스 호출
        stockService.fetchAndSaveDailyData(marketCode, stockCode, startDate, endDate, periodCode);

        return ResponseEntity.status(HttpStatus.CREATED).body("데일리 주식 저장 완료");
    }

    @GetMapping("/minute-data")
    public ResponseEntity<?> mStockData(
            @RequestParam String marketCode,
            @RequestParam String stockCode,
            @RequestParam String startHour,
            @RequestParam String date,
            @RequestParam String periodCode) {
        minuteStockService.fetchAndSaveMinuteData(
                marketCode, stockCode, date, startHour, periodCode);
        return ResponseEntity.status(HttpStatus.CREATED).body("분 주식 저장 완료");
    }

    @GetMapping("/today-minute-data")
    public ResponseEntity<?> minuteStockData(
            @RequestParam String marketCode,
            @RequestParam String stockCode,
            @RequestParam String startTime,
            @RequestParam String periodCode,
            @RequestParam String clsCode) {

        todayMinuteStockService.fetchAndSaveCurrentDayMinuteData(
                marketCode, stockCode, startTime, periodCode, clsCode);
        return ResponseEntity.status(HttpStatus.CREATED).body("분 주식 저장 완료");
    }
}
