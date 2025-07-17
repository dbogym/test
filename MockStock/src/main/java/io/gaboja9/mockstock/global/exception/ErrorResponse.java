package io.gaboja9.mockstock.global.exception;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponse {
    private String message;
    private String code;
    private int status;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private LocalDateTime timestamp; // 에러 발생 시각

    private List<FieldError> errors; // 필드 단위 에러 목록 (예: validation 실패)

    @Builder
    public ErrorResponse(String code, String message, int status, List<FieldError> errors) {
        this.code = code;
        this.message = message;
        this.status = status;
        this.errors = errors;
        this.timestamp = LocalDateTime.now();
    }

    // 에러 필드가 없는 경우
    public static ErrorResponse of(String code, String message, int status) {
        return ErrorResponse.builder().code(code).message(message).status(status).build();
    }

    // 에러 필드가 있는 경우 (예: 유효성 검사 실패)
    public static ErrorResponse of(
            String code, String message, int status, List<FieldError> errors) {
        return ErrorResponse.builder()
                .code(code)
                .message(message)
                .status(status)
                .errors(errors)
                .build();
    }

    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    public static class FieldError {
        private String field; // 어떤 필드에서 (예: {"filed" : "age",
        private String value; // 어떤 값이         "value" : "-1",
        private String reason; // 어떤 이유로        "reason" : "0 이상이어야 합니다."})

        @Builder
        public FieldError(String field, String value, String reason) {
            this.field = field;
            this.value = value;
            this.reason = reason;
        }

        public static FieldError of(String field, String value, String reason) {
            return FieldError.builder().field(field).value(value).reason(reason).build();
        }
    }
}
