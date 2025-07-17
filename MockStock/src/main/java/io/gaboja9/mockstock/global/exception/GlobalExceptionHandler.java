package io.gaboja9.mockstock.global.exception;

import lombok.extern.slf4j.Slf4j;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(BaseException.class)
    protected ResponseEntity<ErrorResponse> handleBaseException(BaseException e) {
        log.error("BaseException: {}", e.getMessage(), e);

        ErrorCode errorCode = e.getErrorCode();
        ErrorResponse errorResponse =
                ErrorResponse.of(
                        errorCode.getCode(), e.getMessage(), errorCode.getStatus().value());

        return ResponseEntity.status(errorCode.getStatus()).body(errorResponse);
    }

    // @Valid 검증 실패
    @ExceptionHandler(MethodArgumentNotValidException.class)
    protected ResponseEntity<ErrorResponse> handleMethodArgumentNotValidException(
            MethodArgumentNotValidException e) {
        log.error("MethodArgumentNotValidException: {}", e.getMessage());

        List<ErrorResponse.FieldError> fieldErrors =
                e.getBindingResult().getFieldErrors().stream()
                        .map(
                                error ->
                                        ErrorResponse.FieldError.of(
                                                error.getField(),
                                                error.getRejectedValue() != null
                                                        ? error.getRejectedValue().toString()
                                                        : "",
                                                error.getDefaultMessage()))
                        .collect(Collectors.toList());

        ErrorResponse response =
                ErrorResponse.of(
                        ErrorCode.INVALID_INPUT_VALUE.getCode(),
                        ErrorCode.INVALID_INPUT_VALUE.getMessage(),
                        ErrorCode.INVALID_INPUT_VALUE.getStatus().value(),
                        fieldErrors);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    // 처리되지 않은 모든 예외
    @ExceptionHandler(Exception.class)
    protected ResponseEntity<ErrorResponse> handleException(Exception e) {
        log.error("Exception: {}", e.getMessage());

        ErrorResponse response =
                ErrorResponse.of(
                        ErrorCode.INTERNAL_SERVER_ERROR.getCode(),
                        ErrorCode.INTERNAL_SERVER_ERROR.getMessage(),
                        ErrorCode.INTERNAL_SERVER_ERROR.getStatus().value());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}
