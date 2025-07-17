package io.gaboja9.mockstock.domain.payments.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "결제 응답")
public class PaymentResponse {

    @Schema(description = "성공 여부", example = "true")
    private boolean success;

    @Schema(description = "응답 메시지", example = "결제 준비 완료")
    private String message;

    @Schema(
            description = "응답 데이터",
            oneOf = {KakaoPayReadyResponse.class, KakaoPayApproveResponse.class})
    private Object data;

    public static PaymentResponse success(String message, Object data) {
        return new PaymentResponse(true, message, data);
    }

    public static PaymentResponse fail(String message) {
        return new PaymentResponse(false, message, null);
    }
}
