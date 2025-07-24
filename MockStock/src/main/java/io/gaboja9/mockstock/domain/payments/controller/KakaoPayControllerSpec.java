package io.gaboja9.mockstock.domain.payments.controller;

import io.gaboja9.mockstock.domain.auth.dto.MembersDetails;
import io.gaboja9.mockstock.domain.payments.dto.PaymentRequest;
import io.gaboja9.mockstock.domain.payments.dto.PaymentResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
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
                                @Content(
                                        schema = @Schema(implementation = PaymentResponse.class),
                                        examples =
                                                @ExampleObject(
                                                        name = "결제 준비 성공",
                                                        value =
                                                                """
                                                                        {
                                                                            "success": true,
                                                                            "message": "결제 준비 완료",
                                                                            "data": {
                                                                                "tid": "T87734d3620347052c46",
                                                                                "next_redirect_pc_url": "https://online-payment.kakaopay.com/mockup/bridge/pc/pg/one-time/payment/bcd3325a4ea71ed80c6056c4134c88987c1705066247638c9fea68b507ccd57e",
                                                                                "next_redirect_mobile_url": "https://online-payment.kakaopay.com/mockup/bridge/mobile-web/pg/one-time/payment/bcd3325a4ea71ed80c6056c4134c88987c1705066247638c9fea68b507ccd57e",
                                                                                "next_redirect_app_url": "https://online-payment.kakaopay.com/mockup/bridge/mobile-app/pg/one-time/payment/bcd3325a4ea71ed80c6056c4134c88987c1705066247638c9fea68b507ccd57e",
                                                                                "android_app_scheme": "kakaotalk://kakaopay/pg?url=https://online-pay.kakaopay.com/pay/mockup/bcd3325a4ea71ed80c6056c4134c88987c1705066247638c9fea68b507ccd57e",
                                                                                "ios_app_scheme": "kakaotalk://kakaopay/pg?url=https://online-pay.kakaopay.com/pay/mockup/bcd3325a4ea71ed80c6056c4134c88987c1705066247638c9fea68b507ccd57e",
                                                                                "created_at": "2025-07-16T14:12:51"
                                                                            }
                                                                        }
                                                                """))),
                @ApiResponse(
                        responseCode = "400",
                        description = "잘못된 요청",
                        content =
                                @Content(schema = @Schema(implementation = PaymentResponse.class)))
            })
    ResponseEntity<PaymentResponse> paymentReady(
            @Parameter(description = "결제 요청 정보", required = true) @RequestBody
                    PaymentRequest request,
            @AuthenticationPrincipal MembersDetails membersDetails);

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
