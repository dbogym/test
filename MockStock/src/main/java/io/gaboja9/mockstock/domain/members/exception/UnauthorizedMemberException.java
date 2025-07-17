package io.gaboja9.mockstock.domain.members.exception;

import io.gaboja9.mockstock.global.exception.BaseException;
import io.gaboja9.mockstock.global.exception.ErrorCode;

public class UnauthorizedMemberException extends BaseException {
    public UnauthorizedMemberException() {
        super(ErrorCode.UNAUTHORIZED_MEMBER);
    }
}
