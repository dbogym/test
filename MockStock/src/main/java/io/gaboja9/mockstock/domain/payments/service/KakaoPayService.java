package io.gaboja9.mockstock.domain.payments.service;

import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.members.exception.NotFoundMemberException;
import io.gaboja9.mockstock.domain.members.repository.MembersRepository;
import io.gaboja9.mockstock.domain.payments.dto.KakaoPayApproveResponse;
import io.gaboja9.mockstock.domain.payments.dto.KakaoPayReadyResponse;
import io.gaboja9.mockstock.domain.payments.entity.PaymentHistory;
import io.gaboja9.mockstock.domain.payments.entity.PaymentStatus;
import io.gaboja9.mockstock.domain.payments.exception.PaymentException;
import io.gaboja9.mockstock.domain.payments.exception.PaymentHistoryException;
import io.gaboja9.mockstock.domain.payments.repository.PaymentHistoryRepository;
import io.gaboja9.mockstock.global.exception.ErrorCode;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class KakaoPayService {

    @Value("${kakaopay.secret-key}")
    private String secretKey;

    @Value("${kakaopay.base-url}")
    private String baseUrl;

    @Value("${kakaopay.cid}")
    private String cid;

    @Value("${app.base-url}")
    private String appBaseUrl;

    private final RestTemplate restTemplate;
    private final PaymentHistoryRepository paymentHistoryRepository;
    private final MembersRepository membersRepository;

    public KakaoPayReadyResponse paymentReady(Long memberId, int amount) {

        Members member =
                membersRepository
                        .findById(memberId)
                        .orElseThrow(() -> new NotFoundMemberException(memberId));

        String partnerOrderId = generateOrderId();

        PaymentHistory paymentHistory =
                PaymentHistory.builder()
                        .members(member)
                        .partnerOrderId(partnerOrderId)
                        .amount(amount)
                        .status(PaymentStatus.READY)
                        .build();

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "SECRET_KEY " + secretKey);
        headers.setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> params = new HashMap<>();
        params.put("cid", cid);
        params.put("partner_order_id", partnerOrderId);
        params.put("partner_user_id", String.valueOf(memberId));
        params.put("item_name", "모의투자 포인트 충전");
        params.put("quantity", "1");
        params.put("total_amount", String.valueOf(amount));
        params.put("tax_free_amount", "0");
        params.put("approval_url", appBaseUrl + "/payments/approve");
        params.put("cancel_url", appBaseUrl + "/payments/cancel");
        params.put("fail_url", appBaseUrl + "/payments/fail");

        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(params, headers);

        try {
            ResponseEntity<KakaoPayReadyResponse> response =
                    restTemplate.exchange(
                            baseUrl + "/online/v1/payment/ready",
                            HttpMethod.POST,
                            entity,
                            KakaoPayReadyResponse.class);

            KakaoPayReadyResponse readyResponse = response.getBody();

            if (readyResponse == null) {
                throw new PaymentException(ErrorCode.KAKAOPAY_API_ERROR);
            }

            paymentHistory.setTid(readyResponse.getTid());
            paymentHistoryRepository.save(paymentHistory);

            return readyResponse;
        } catch (Exception e) {
            paymentHistory.setStatus(PaymentStatus.FAILED);
            paymentHistoryRepository.save(paymentHistory);
            throw new PaymentException(ErrorCode.PAYMENT_READY_FAILED);
        }
    }

    public KakaoPayApproveResponse paymentApprove(String pgToken, Long memberId) {

        String tid = getLatestReadyTid(memberId);

        PaymentHistory paymentHistory =
                paymentHistoryRepository
                        .findByTidAndMembersId(tid, memberId)
                        .orElseThrow(
                                () ->
                                        new PaymentHistoryException(
                                                ErrorCode.PAYMENT_HISTORY_NOT_FOUND));

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "SECRET_KEY " + secretKey);
        headers.setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> params = new HashMap<>();
        params.put("cid", cid);
        params.put("tid", tid);
        params.put("partner_order_id", paymentHistory.getPartnerOrderId());
        params.put("partner_user_id", String.valueOf(memberId));
        params.put("pg_token", pgToken);

        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(params, headers);

        try {
            ResponseEntity<KakaoPayApproveResponse> response =
                    restTemplate.exchange(
                            baseUrl + "/online/v1/payment/approve",
                            HttpMethod.POST,
                            entity,
                            KakaoPayApproveResponse.class);

            KakaoPayApproveResponse approveResponse = response.getBody();

            if (approveResponse != null) {

                Members member = paymentHistory.getMembers();
                member.setCashBalance(member.getCashBalance() + paymentHistory.getAmount());
                membersRepository.save(member);

                paymentHistory.setStatus(PaymentStatus.APPROVED);
                paymentHistoryRepository.save(paymentHistory);
            }
            return approveResponse;

        } catch (Exception e) {
            paymentHistory.setStatus(PaymentStatus.FAILED);
            paymentHistoryRepository.save(paymentHistory);
            throw new PaymentException(ErrorCode.PAYMENT_APPROVE_FAILED);
        }
    }

    public void paymentCancel(String tid, Long membersId) {
        PaymentHistory paymentHistory =
                paymentHistoryRepository
                        .findByTidAndMembersId(tid, membersId)
                        .orElseThrow(() -> new RuntimeException("임시 오류"));

        paymentHistory.setStatus(PaymentStatus.CANCELLED);
        paymentHistoryRepository.save(paymentHistory);
    }

    public void paymentFail(String tid, Long membersId) {
        PaymentHistory paymentHistory =
                paymentHistoryRepository
                        .findByTidAndMembersId(tid, membersId)
                        .orElseThrow(
                                () ->
                                        new PaymentHistoryException(
                                                ErrorCode.PAYMENT_HISTORY_NOT_FOUND));

        paymentHistory.setStatus(PaymentStatus.FAILED);
        paymentHistoryRepository.save(paymentHistory);
    }

    private String generateOrderId() {
        return "ORDER_" + System.currentTimeMillis() + "_" + (int) (Math.random() * 1000);
    }

    public String getLatestReadyTid(Long memberId) {
        return paymentHistoryRepository.findLatestTidByMemberAndStatusReady(memberId).orElse(null);
    }
}
