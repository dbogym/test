package io.gaboja9.mockstock.domain.orders.exception;

import io.gaboja9.mockstock.global.exception.BaseException;
import io.gaboja9.mockstock.global.exception.ErrorCode;

public class NotEnoughCashException extends BaseException {

    public NotEnoughCashException(int cashBalance) {
        super(ErrorCode.NOT_ENOUGH_CASH, "잔액이 부족합니다. 잔액 : " + cashBalance);
    }
}
