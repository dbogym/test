package io.gaboja9.mockstock.domain.stock.exception;

import io.gaboja9.mockstock.global.exception.BaseException;
import io.gaboja9.mockstock.global.exception.ErrorCode;

public class NotFoundStockException extends BaseException {
    public NotFoundStockException() {
        super(ErrorCode.NOT_FOUNT_STOCK);
    }

    public NotFoundStockException(String stockCode) {
        super(ErrorCode.NOT_FOUNT_STOCK, "주식을 찾을 수 없습니다. ID: " + stockCode);
    }
}
