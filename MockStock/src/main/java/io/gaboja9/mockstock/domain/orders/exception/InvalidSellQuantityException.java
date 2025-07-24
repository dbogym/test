package io.gaboja9.mockstock.domain.orders.exception;

import io.gaboja9.mockstock.global.exception.BaseException;
import io.gaboja9.mockstock.global.exception.ErrorCode;

public class InvalidSellQuantityException extends BaseException {

    public InvalidSellQuantityException(int quantity) {
        super(ErrorCode.INVALID_SELL_QUANTITY, "보유 수량보다 많은 주식을 매도할 수 없습니다. 보유 수량: " + quantity);
    }
}
