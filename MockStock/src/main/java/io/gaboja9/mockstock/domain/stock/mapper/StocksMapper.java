package io.gaboja9.mockstock.domain.stock.mapper;

import io.gaboja9.mockstock.domain.stock.dto.StockResponse;
import io.gaboja9.mockstock.domain.stock.entity.Stocks;

import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class StocksMapper {

    public StockResponse toDto(Stocks stock) {
        return StockResponse.builder()
                .stockCode(stock.getStockCode())
                .stockName(stock.getStockName())
                .build();
    }

    public List<StockResponse> toDtoList(List<Stocks> stocks) {
        return stocks.stream().map(this::toDto).toList();
    }
}
