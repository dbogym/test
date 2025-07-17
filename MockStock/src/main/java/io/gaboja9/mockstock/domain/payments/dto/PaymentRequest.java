package io.gaboja9.mockstock.domain.payments.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "결제 요청")
public class PaymentRequest {

    @Schema(description = "충전 금액", example = "10000", required = true, minimum = "1")
    @NotNull
    @Min(value = 1, message = "충전 금액은 1원 이상이어야 합니다.")
    private int chargeAmount;
}
