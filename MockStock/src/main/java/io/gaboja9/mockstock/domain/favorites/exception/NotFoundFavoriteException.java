package io.gaboja9.mockstock.domain.favorites.exception;

import io.gaboja9.mockstock.global.exception.BaseException;
import io.gaboja9.mockstock.global.exception.ErrorCode;

public class NotFoundFavoriteException extends BaseException {
    public NotFoundFavoriteException(Long memberId, String stockCode) {
        super(
                ErrorCode.NOT_FOUND_FAVORITE,
                String.format("Member ID: %d, Stock code: %s", memberId, stockCode));
    }
}
