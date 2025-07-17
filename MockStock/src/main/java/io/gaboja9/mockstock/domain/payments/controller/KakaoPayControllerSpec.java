package io.gaboja9.mockstock.domain.payments.controller;

import io.gaboja9.mockstock.domain.payments.dto.PaymentRequest;
import io.gaboja9.mockstock.domain.payments.dto.PaymentResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

@Tag(name = "KakaoPay", description = "카카오페이 결제 API")
public interface KakaoPayControllerSpec {

    @Operation(
            summary = "결제 준비",
            description =
                    "카카오페이 결제를 준비하고 결제 URL을 반환합니다. 다른 API는 리다이렉션 API라 따로 사용하진 않고 해당 API를 통해 반환된"
                            + " next_redirect_pc_url 주소로 결제를 진행합니다.")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "결제 준비 성공",
                        content =
                                @Content(schema = @Schema(implementation = PaymentResponse.class))),
                @ApiResponse(
                        responseCode = "400",
                        description = "잘못된 요청",
                        content =
                                @Content(schema = @Schema(implementation = PaymentResponse.class)))
            })
    ResponseEntity<PaymentResponse> paymentReady(
            @Parameter(description = "결제 요청 정보", required = true) @RequestBody
                    PaymentRequest request);

    @Operation(summary = "결제 승인", description = "카카오페이 결제를 승인합니다.")
    @ApiResponses(
            value = {
                @ApiResponse(responseCode = "200", description = "결제 승인 성공"),
                @ApiResponse(responseCode = "400", description = "결제 승인 실패")
            })
    ResponseEntity<PaymentResponse> paymentApprove(
            @Parameter(description = "카카오페이 결제 고유 토큰", required = true, example = "sample_pg_token")
                    @RequestParam("pg_token")
                    String pgToken);

    @Operation(summary = "결제 취소", description = "진행 중인 결제를 취소합니다.")
    @ApiResponses(
            value = {
                @ApiResponse(responseCode = "200", description = "결제 취소 성공"),
                @ApiResponse(responseCode = "400", description = "결제 취소 실패")
            })
    ResponseEntity<PaymentResponse> paymentCancel(
            @Parameter(description = "카카오페이 거래 고유 번호", required = true, example = "T1234567890")
                    @RequestParam("tid")
                    String tid);

    @Operation(summary = "결제 실패 처리", description = "카카오페이 결제 실패를 처리합니다.")
    @ApiResponses(
            value = {
                @ApiResponse(responseCode = "200", description = "결제 실패 처리 성공"),
                @ApiResponse(responseCode = "400", description = "결제 실패 처리 실패")
            })
    ResponseEntity<PaymentResponse> paymentFail(
            @Parameter(description = "카카오페이 거래 고유 번호", required = true, example = "T1234567890")
                    @RequestParam("tid")
                    String tid);
}
