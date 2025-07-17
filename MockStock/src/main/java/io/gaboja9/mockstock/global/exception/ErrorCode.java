package io.gaboja9.mockstock.global.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    // 공통 에러
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "GLOBAL-001", "서버 내부 오류가 발생했습니다."),
    INVALID_INPUT_VALUE(HttpStatus.BAD_REQUEST, "GLOBAL-002", "잘못된 입력값입니다."),

    // 사용자 관련 에러
    NOT_FOUNT_MEMBER(HttpStatus.NOT_FOUND, "MEMBER-001", "사용자를 찾을 수 없습니다."),
    UNAUTHORIZED_MEMBER(HttpStatus.UNAUTHORIZED, "MEMBER-002", "인증되지 않은 사용자입니다."),

    // 결제 관련 에러
    PAYMENT_READY_FAILED(HttpStatus.BAD_REQUEST, "PAYMENT-001", "결제 준비 중 오류가 발생했습니다."),
    PAYMENT_APPROVE_FAILED(HttpStatus.BAD_REQUEST, "PAYMENT-002", "결제 승인 중 오류가 발생했습니다."),
    PAYMENT_HISTORY_NOT_FOUND(HttpStatus.NOT_FOUND, "PAYMENT-003", "결제 내역을 찾을 수 없습니다."),
    PAYMENT_TID_NOT_FOUND(HttpStatus.NOT_FOUND, "PAYMENT-004", "결제 트랜잭션 ID를 찾을 수 없습니다."),
    KAKAOPAY_API_ERROR(HttpStatus.BAD_GATEWAY, "PAYMENT-005", "카카오페이 API 호출 중 오류가 발생했습니다."),
    INVALID_PAYMENT_AMOUNT(HttpStatus.BAD_REQUEST, "PAYMENT-006", "잘못된 결제 금액입니다."),
    PAYMENT_ALREADY_PROCESSED(HttpStatus.CONFLICT, "PAYMENT-007", "이미 처리된 결제입니다."),

    // 인증 관련 에러
    JWT_TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "JWT-001", "토큰이 만료되었습니다."),
    JWT_TOKEN_INVALID(HttpStatus.UNAUTHORIZED, "JWT-002", "유효하지 않은 토큰입니다."),
    JWT_TOKEN_MALFORMED(HttpStatus.UNAUTHORIZED, "JWT-003", "잘못된 형식의 토큰입니다."),
    JWT_SIGNATURE_INVALID(HttpStatus.UNAUTHORIZED, "JWT-004", "토큰 서명이 유효하지 않습니다."),
    JWT_TOKEN_UNSUPPORTED(HttpStatus.UNAUTHORIZED, "JWT-005", "지원되지 않는 토큰입니다."),

    INVALID_CREDENTIALS(HttpStatus.UNAUTHORIZED, "AUTH-001", "이메일 또는 비밀번호가 올바르지 않습니다."),
    EMAIL_ALREADY_EXISTS(HttpStatus.CONFLICT, "AUTH-002", "이미 존재하는 이메일입니다."),
    PASSWORD_MISMATCH(HttpStatus.BAD_REQUEST, "AUTH-003", "비밀번호가 일치하지 않습니다."),
    INVALID_VERIFICATION_CODE(HttpStatus.BAD_REQUEST, "AUTH-004", "인증코드가 올바르지 않습니다."),
    VERIFICATION_CODE_EXPIRED(HttpStatus.BAD_REQUEST, "AUTH-005", "인증코드가 만료되었습니다."),
    WEAK_PASSWORD(HttpStatus.BAD_REQUEST, "AUTH-006", "비밀번호 강도가 부족합니다."),
    AUTH_RESEND_TOO_EARLY(HttpStatus.BAD_REQUEST, "AUTH-007", "인증코드는 {0}초 후에 재발송할 수 있습니다."),
    SOCIAL_LOGIN_REQUIRED(HttpStatus.BAD_REQUEST, "AUTH-006", "{0} 계정이 존재합니다. {0} 로그인을 이용해주세요.");

    private final HttpStatus status;
    private final String code;
    private final String message;
}
