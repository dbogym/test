package io.gaboja9.mockstock.domain.members.exception;

public class NotFoundMailException extends RuntimeException {
    public NotFoundMailException(String message) {
        super(message);
    }
}
