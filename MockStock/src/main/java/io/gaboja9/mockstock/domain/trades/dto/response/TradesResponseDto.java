package io.gaboja9.mockstock.domain.trades.dto.response;

import io.gaboja9.mockstock.domain.trades.entity.TradeType;
import io.swagger.v3.oas.annotations.media.Schema;

import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@Builder
public class TradesResponseDto {

    @Schema(description = "매수/매도")
    private TradeType tradeType;

    @Schema(description = "거래한 주식 코드")
    private String stockCode;

    @Schema(description = "거래한 주식 이름")
    private String stockName;

    @Schema(description = "거래한 가격")
    private int price;

    @Schema(description = "거래한 주식 수")
    private int quantity;

    @Schema(description = "거래한 총 금액")
    private int totalAmount;

    @Schema(description = "거래한 시각")
    private LocalDateTime tradeDateTime;
}
