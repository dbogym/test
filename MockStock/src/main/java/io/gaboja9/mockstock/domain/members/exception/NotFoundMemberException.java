package io.gaboja9.mockstock.domain.members.exception;

import io.gaboja9.mockstock.global.exception.BaseException;
import io.gaboja9.mockstock.global.exception.ErrorCode;

public class NotFoundMemberException extends BaseException {
    public NotFoundMemberException() {
        super(ErrorCode.NOT_FOUNT_MEMBER);
    }

    public NotFoundMemberException(String message) {
        super(ErrorCode.NOT_FOUNT_MEMBER, message);
    }

    public NotFoundMemberException(Long memberId) {
        super(ErrorCode.NOT_FOUNT_MEMBER, "멤버를 찾을 수 없습니다. ID: " + memberId);
    }
}
