package io.gaboja9.mockstock.domain.portfolios.exception;

import io.gaboja9.mockstock.global.exception.BaseException;
import io.gaboja9.mockstock.global.exception.ErrorCode;

public class NotFoundPortfolioException extends BaseException {

    public NotFoundPortfolioException() {
        super(ErrorCode.NOT_FOUND_PORTFOLIO, "해당 주식을 보유하고 있지 않습니다.");
    }
}
