package io.gaboja9.mockstock.domain.payments.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import lombok.Getter;

@Getter
@Schema(description = "카카오페이 결제 승인 응답")
public class KakaoPayApproveResponse {

    @Schema(description = "요청 고유 번호", example = "A5CX9272438083FC")
    private String aid;

    @Schema(description = "결제 고유 번호", example = "T2206222222222222")
    private String tid;

    @Schema(description = "가맹점 코드", example = "TC0ONETIME")
    private String cid;

    @Schema(description = "정기결제용 ID", example = "S2206222222222222")
    private String sid;

    @Schema(description = "가맹점 주문 번호", example = "ORDER123")
    private String partner_order_id;

    @Schema(description = "가맹점 회원 ID", example = "USER123")
    private String partner_user_id;

    @Schema(description = "결제 수단", example = "CARD")
    private String payment_method_type;

    @Schema(description = "결제 상태", example = "SUCCESS_PAYMENT")
    private String status;

    @Schema(description = "결제 금액 정보")
    private AmountDetail amount;

    @Schema(description = "카드 정보")
    private CardInfo card_info;

    @Schema(description = "상품 이름", example = "포인트 충전")
    private String item_name;

    @Schema(description = "상품 코드", example = "POINT_CHARGE")
    private String item_code;

    @Schema(description = "상품 수량", example = "1")
    private int quantity;

    @Schema(description = "결제 요청 시간", example = "2024-06-22T15:30:00")
    private String created_at;

    @Schema(description = "결제 승인 시간", example = "2024-06-22T15:35:00")
    private String approved_at;

    @Schema(description = "결제 승인 요청에 대해 저장하고 싶은 값")
    private String payload;

    @Schema(description = "결제 금액 상세 정보")
    public static class AmountDetail {
        @Schema(description = "전체 결제 금액", example = "10000")
        private int total;

        @Schema(description = "비과세 금액", example = "0")
        private int tax_free;

        @Schema(description = "부가세 금액", example = "909")
        private int vat;

        @Schema(description = "사용한 포인트", example = "0")
        private int point;

        @Schema(description = "할인 금액", example = "0")
        private int discount;

        @Schema(description = "컵 보증금", example = "0")
        private int green_deposit;
    }

    @Schema(description = "카드 정보")
    public static class CardInfo {
        @Schema(description = "카카오페이 매입사명", example = "카카오페이")
        private String kakaopay_purchase_corp;

        @Schema(description = "카카오페이 매입사 코드", example = "KAKAOPAY")
        private String kakaopay_purchase_corp_code;

        @Schema(description = "카카오페이 발급사명", example = "신한카드")
        private String kakaopay_issuer_corp;

        @Schema(description = "카카오페이 발급사 코드", example = "SHINHAN")
        private String kakaopay_issuer_corp_code;

        @Schema(description = "카드 BIN", example = "123456")
        private String bin;

        @Schema(description = "카드 타입", example = "CREDIT")
        private String card_type;

        @Schema(description = "할부 개월 수", example = "00")
        private String install_month;

        @Schema(description = "카드사 승인번호", example = "12345678")
        private String approved_id;

        @Schema(description = "카드사 가맹점 번호", example = "12345")
        private String card_mid;

        @Schema(description = "무이자할부 YN", example = "N")
        private String interest_free_install;

        @Schema(description = "할부 타입", example = "CARD_INSTALLMENT")
        private String installment_type;

        @Schema(description = "카드 상품 코드", example = "CARD001")
        private String card_item_code;
    }
}
