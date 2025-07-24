package io.gaboja9.mockstock.domain.favorites.exception;

import io.gaboja9.mockstock.global.exception.BaseException;
import io.gaboja9.mockstock.global.exception.ErrorCode;

public class FavoriteAlreadyExistException extends BaseException {

    public FavoriteAlreadyExistException(String stockCode) {
        super(ErrorCode.FAVORITE_ALREADY_EXISTS, "Stock code: " + stockCode);
    }
}
