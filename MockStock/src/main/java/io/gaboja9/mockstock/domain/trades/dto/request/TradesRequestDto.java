package io.gaboja9.mockstock.domain.trades.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;

import jakarta.validation.constraints.NotNull;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDate;

@Getter
@Setter
@Builder
public class TradesRequestDto {

    @Schema(description = "검색할 주식 코드", nullable = true)
    private String stockCode;

    @Schema(description = "검색할 주식 이름", nullable = true)
    private String stockName;

    @Schema(description = "검색 시작 날짜")
    @NotNull
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
    private LocalDate startDate;

    @Schema(description = "검색 종료 날짜")
    @NotNull
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
    private LocalDate endDate;
}
