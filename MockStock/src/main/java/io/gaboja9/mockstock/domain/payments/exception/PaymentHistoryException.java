package io.gaboja9.mockstock.domain.payments.exception;

import io.gaboja9.mockstock.global.exception.BaseException;
import io.gaboja9.mockstock.global.exception.ErrorCode;

public class PaymentHistoryException extends BaseException {
    public PaymentHistoryException(ErrorCode errorCode) {
        super(errorCode);
    }
}
