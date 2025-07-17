package io.gaboja9.mockstock.domain.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "회원가입 요청")
public class SignUpRequestDto {

    @Schema(description = "이름", example = "홍길동")
    @NotBlank(message = "이름을 입력해주세요")
    private String name;

    @Schema(description = "이메일", example = "test@example.com")
    @NotBlank(message = "이메일을 입력해주세요")
    @Email(message = "올바른 이메일 형식이 아닙니다")
    private String email;

    @Schema(description = "인증코드", example = "123456")
    @NotBlank(message = "6자리 인증코드를 입력해주세요")
    @Size(min = 6, max = 6, message = "인증코드는 6자리여야 합니다")
    private String verificationCode;

    @Schema(description = "비밀번호", example = "password123!")
    @NotBlank(message = "비밀번호를 입력해주세요")
    @Size(min = 8, message = "비밀번호는 8자 이상 이어야 합니다")
    private String password;

    @Schema(description = "비밀번호 확인", example = "password123!")
    @NotBlank(message = "비밀번호를 다시 입력해주세요")
    private String passwordConfirm;
}
