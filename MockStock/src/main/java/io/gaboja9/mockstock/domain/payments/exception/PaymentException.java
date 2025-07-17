package io.gaboja9.mockstock.domain.payments.exception;

import io.gaboja9.mockstock.global.exception.BaseException;
import io.gaboja9.mockstock.global.exception.ErrorCode;

public class PaymentException extends BaseException {
    public PaymentException(ErrorCode errorCode) {
        super(errorCode);
    }
}
