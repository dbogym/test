package io.gaboja9.mockstock.domain.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "인증 관련 응답")
public class AuthResponseDto {

    @Schema(description = "성공 여부", example = "true")
    private boolean success;

    @Schema(description = "응답 메시지", example = "회원가입이 완료되었습니다")
    private String message;

    @Schema(description = "응답 데이터")
    private Object data;

    public static AuthResponseDto success(String message) {
        return AuthResponseDto.builder().success(true).message(message).build();
    }

    public static AuthResponseDto success(String message, Object data) {
        return AuthResponseDto.builder().success(true).message(message).data(data).build();
    }

    public static AuthResponseDto fail(String message) {
        return AuthResponseDto.builder().success(true).message(message).build();
    }
}
