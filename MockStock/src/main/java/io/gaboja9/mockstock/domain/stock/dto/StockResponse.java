package io.gaboja9.mockstock.domain.stock.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor
public class StockResponse {

    private String stockCode;
    private String stockName;
}
