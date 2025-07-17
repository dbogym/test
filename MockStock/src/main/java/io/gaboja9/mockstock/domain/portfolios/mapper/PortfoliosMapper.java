package io.gaboja9.mockstock.domain.portfolios.mapper;

import io.gaboja9.mockstock.domain.portfolios.dto.response.PortfolioResponseDto;
import io.gaboja9.mockstock.domain.portfolios.entity.Portfolios;
// import io.gaboja9.mockstock.global.Influx.InfluxQueryService;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class PortfoliosMapper {

    //    private final InfluxQueryService influxQueryService;

    public PortfolioResponseDto toDto(Portfolios p) {
        int quantity = p.getQuantity();
        int avgPrice = p.getAvgPrice();
        //        int currentPrice = influxQueryService.getCurrentPrice(p.getStockCode());
        int currentPrice = 100;

        int evaluationAmount = currentPrice * quantity;
        int profit = (currentPrice - avgPrice) * quantity;
        int investment = avgPrice * quantity;
        double profitRate =
                (investment == 0
                        ? 0.00
                        : Math.round((double) profit / investment * 100 * 100) / 100.0);

        return PortfolioResponseDto.builder()
                .stockCode(p.getStockCode())
                .stockName(p.getStockName())
                .quantity(quantity)
                .avgPrice(avgPrice)
                .currentPrice(currentPrice)
                .evaluationAmount(evaluationAmount)
                .profit(profit)
                .profitRate(profitRate)
                .build();
    }
}
