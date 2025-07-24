package io.gaboja9.mockstock.global.websocket.exeception;

import io.gaboja9.mockstock.global.exception.BaseException;
import io.gaboja9.mockstock.global.exception.ErrorCode;

public class StockException extends BaseException {

    public StockException() {
        super(ErrorCode.INVALID_STOCK); // 기본 에러코드 설정
    }

    public StockException(String message) {
        super(ErrorCode.INVALID_STOCK, message); // 커스텀 메시지 허용
    }

    public StockException(String message, Throwable cause) {
        super(ErrorCode.INVALID_STOCK, message, cause); // 예외 체이닝
    }
}
