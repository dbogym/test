package io.gaboja9.mockstock.domain.orders.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class OrdersMarketTypeRequestDto {

    @NotBlank
    @Schema(description = "매수/매도할 주식 코드")
    private String stockCode;

    @NotBlank
    @Schema(description = "매수/매도할 주식 이름")
    private String stockName;

    @NotNull
    @Schema(description = "매수/매도 수량")
    private int quantity;
}
