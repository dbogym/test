package io.gaboja9.mockstock.domain.trades.mapper;

import io.gaboja9.mockstock.domain.trades.dto.response.TradesResponseDto;
import io.gaboja9.mockstock.domain.trades.entity.Trades;

import org.springframework.stereotype.Component;

@Component
public class TradesMapper {
    public TradesResponseDto toDto(Trades t) {
        return TradesResponseDto.builder()
                .stockCode(t.getStockCode())
                .stockName(t.getStockName())
                .tradeType(t.getTradeType())
                .quantity(t.getQuantity())
                .price(t.getPrice())
                .totalAmount(t.getPrice() * t.getQuantity())
                .tradeDateTime(t.getCreatedAt())
                .build();
    }
}
