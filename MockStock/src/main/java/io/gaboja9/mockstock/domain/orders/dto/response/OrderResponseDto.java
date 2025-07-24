package io.gaboja9.mockstock.domain.orders.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class OrderResponseDto {

    @Schema(description = "거래 실행 여부")
    private boolean executed;

    @Schema(description = "거래 안내 메시지")
    private String message;

    @Schema(description = "거래 가격")
    private int price;
}
