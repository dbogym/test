package io.gaboja9.mockstock.domain.payments.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import lombok.Getter;

@Getter
@Schema(description = "카카오페이 결제 준비 응답")
public class KakaoPayReadyResponse {

    @Schema(description = "결제 고유 번호", example = "T2206222222222222")
    private String tid;

    @Schema(
            description = "PC웹 카카오페이 결제 페이지 URL",
            example = "https://online-pay.kakao.com/mockup/v1/...")
    private String next_redirect_pc_url;

    @Schema(
            description = "모바일 카카오페이 결제 페이지 URL",
            example = "https://online-pay.kakao.com/mockup/v1/...")
    private String next_redirect_mobile_url;

    @Schema(
            description = "카카오페이 앱 결제 페이지 URL",
            example = "https://online-pay.kakao.com/mockup/v1/...")
    private String next_redirect_app_url;

    @Schema(description = "안드로이드 앱 스키마", example = "kakaotalk://kakaopay/...")
    private String android_app_scheme;

    @Schema(description = "iOS 앱 스키마", example = "kakaotalk://kakaopay/...")
    private String ios_app_scheme;

    @Schema(description = "결제 준비 요청 시간", example = "2024-06-22T15:30:00")
    private String created_at;
}
