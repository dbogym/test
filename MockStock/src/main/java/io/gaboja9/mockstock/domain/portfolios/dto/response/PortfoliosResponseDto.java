package io.gaboja9.mockstock.domain.portfolios.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.util.List;

@Getter
@Builder
@AllArgsConstructor
public class PortfoliosResponseDto {

    @Schema(description = "보유중인 현금")
    private int cashBalance;

    @Schema(description = "총 평가금액")
    private int totalEvaluationAmount;

    @Schema(description = "총 손익")
    private int totalProfit;

    @Schema(description = "총 수익률")
    private double totalProfitRate;

    @Schema(description = "주식별 포트폴리오")
    private List<PortfolioResponseDto> portfolios;
}
