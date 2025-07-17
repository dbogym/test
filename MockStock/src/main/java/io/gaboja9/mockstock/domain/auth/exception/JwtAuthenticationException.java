package io.gaboja9.mockstock.domain.auth.exception;

import io.gaboja9.mockstock.global.exception.BaseException;
import io.gaboja9.mockstock.global.exception.ErrorCode;

public class JwtAuthenticationException extends BaseException {
    public JwtAuthenticationException(ErrorCode errorCode) {
        super(errorCode);
    }

    public static JwtAuthenticationException expired() {
        return new JwtAuthenticationException(ErrorCode.JWT_TOKEN_EXPIRED);
    }

    public static JwtAuthenticationException invalid() {
        return new JwtAuthenticationException(ErrorCode.JWT_TOKEN_INVALID);
    }

    public static JwtAuthenticationException malformed() {
        return new JwtAuthenticationException(ErrorCode.JWT_TOKEN_MALFORMED);
    }

    public static JwtAuthenticationException invalidSignature() {
        return new JwtAuthenticationException(ErrorCode.JWT_SIGNATURE_INVALID);
    }

    public static JwtAuthenticationException unsupported() {
        return new JwtAuthenticationException(ErrorCode.JWT_TOKEN_UNSUPPORTED);
    }
}
