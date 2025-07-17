package io.gaboja9.mockstock.domain.portfolios.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class PortfoliosSummary {

    private final int totalEvaluationAmount;

    private final int totalProfit;

    private final double totalProfitRate;
}
