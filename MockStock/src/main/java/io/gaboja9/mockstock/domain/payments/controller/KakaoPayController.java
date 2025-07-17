package io.gaboja9.mockstock.domain.payments.controller;

import io.gaboja9.mockstock.domain.payments.dto.KakaoPayApproveResponse;
import io.gaboja9.mockstock.domain.payments.dto.KakaoPayReadyResponse;
import io.gaboja9.mockstock.domain.payments.dto.PaymentRequest;
import io.gaboja9.mockstock.domain.payments.dto.PaymentResponse;
import io.gaboja9.mockstock.domain.payments.service.KakaoPayService;

import jakarta.validation.Valid;

import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/payments")
@RequiredArgsConstructor
public class KakaoPayController implements KakaoPayControllerSpec {
    private final KakaoPayService kakaoPayService;

    @PostMapping("/ready")
    @Override
    public ResponseEntity<PaymentResponse> paymentReady(
            @Valid @RequestBody PaymentRequest request) {
        try {
            Long memberId = 1L;

            KakaoPayReadyResponse response =
                    kakaoPayService.paymentReady(memberId, request.getChargeAmount());

            return ResponseEntity.ok(PaymentResponse.success("결제 준비 완료", response));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(PaymentResponse.fail("결제 준비 실패: " + e.getMessage()));
        }
    }

    @GetMapping("/approve")
    @Override
    public ResponseEntity<PaymentResponse> paymentApprove(
            @RequestParam("pg_token") String pgToken) {
        try {
            // TODO: JWT 도입시 헤더에서 추출
            Long memberId = 1L;

            KakaoPayApproveResponse response = kakaoPayService.paymentApprove(pgToken, memberId);

            return ResponseEntity.ok(PaymentResponse.success("결제 승인 완료", response));

        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(PaymentResponse.fail("결제 승인 실패: " + e.getMessage()));
        }
    }

    @GetMapping("/cancel")
    @Override
    public ResponseEntity<PaymentResponse> paymentCancel(@RequestParam("tid") String tid) {
        try {
            // TODO: JWT 도입시 헤더에서 추출
            Long memberId = 1L;
            kakaoPayService.paymentCancel(tid, memberId);

            return ResponseEntity.ok(PaymentResponse.success("결제 취소 완료", null));

        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(PaymentResponse.fail("결제 취소 실패: " + e.getMessage()));
        }
    }

    @GetMapping("/fail")
    @Override
    public ResponseEntity<PaymentResponse> paymentFail(@RequestParam("tid") String tid) {
        try {
            Long userId = 1L;
            kakaoPayService.paymentFail(tid, userId);

            return ResponseEntity.ok(PaymentResponse.success("결제 실패 처리 완료", null));

        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(PaymentResponse.fail("결제 실패 처리 실패: " + e.getMessage()));
        }
    }
}
