package io.gaboja9.mockstock.domain.portfolios.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor
public class PortfolioResponseDto {

    @Schema(description = "주식 코드")
    private String stockCode;

    @Schema(description = "주식 이름")
    private String stockName;

    @Schema(description = "거래한 주식 수")
    private int quantity;

    @Schema(description = "평균단가")
    private int avgPrice;

    @Schema(description = "시장가")
    private int currentPrice;

    @Schema(description = "평가금액")
    private int evaluationAmount;

    @Schema(description = "손익")
    private int profit;

    @Schema(description = "수익률")
    private double profitRate;
}
