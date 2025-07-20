package io.gaboja9.mockstock.domain.auth.controller;

import io.gaboja9.mockstock.domain.auth.dto.MembersDetails;
import io.gaboja9.mockstock.domain.auth.dto.TokenPair;
import io.gaboja9.mockstock.domain.auth.dto.request.*;
import io.gaboja9.mockstock.domain.auth.dto.response.AuthResponseDto;
import io.gaboja9.mockstock.domain.auth.entity.RefreshToken;
import io.gaboja9.mockstock.domain.auth.exception.JwtAuthenticationException;
import io.gaboja9.mockstock.domain.auth.repository.TokenRepository;
import io.gaboja9.mockstock.domain.auth.service.EmailVerificationService;
import io.gaboja9.mockstock.domain.auth.service.FormAuthService;
import io.gaboja9.mockstock.domain.auth.service.JwtTokenProvider;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final FormAuthService formAuthService;
    private final EmailVerificationService emailVerificationService;
    private final JwtTokenProvider jwtTokenProvider;
    private final TokenRepository tokenRepository;

    @PostMapping("/signup")
    public ResponseEntity<AuthResponseDto> signUp(
            @Valid @RequestBody SignUpRequestDto signUpRequestDto) {
        log.info("회원가입 요청: {}", signUpRequestDto.getEmail());

        formAuthService.signUp(signUpRequestDto);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(AuthResponseDto.success("회원가입이 완료되었습니다."));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> login(
            @Valid @RequestBody LoginRequestDto loginRequestDto) {

        log.info("로그인 요청:{}", loginRequestDto.getEmail());

        TokenPair tokenPair = formAuthService.login(loginRequestDto);

        return ResponseEntity.ok(AuthResponseDto.success("로그인이 완료되었습니다.", tokenPair));
    }

    @PostMapping("/email")
    public ResponseEntity<AuthResponseDto> email(
            @Valid @RequestBody EmailVerificationRequestDto emailVerificationRequestDto) {
        log.info("이메일 인증코드 발송 요청: {}", emailVerificationRequestDto.getEmail());

        emailVerificationService.sendVerificationCode(emailVerificationRequestDto.getEmail());

        return ResponseEntity.ok(AuthResponseDto.success("인증코드가 발송되었습니다."));
    }

    @PostMapping("/emailVerify")
    public ResponseEntity<AuthResponseDto> emailVerify(
            @Valid @RequestBody EmailVerifyRequestDto dto) {
        log.info("이메일 인증 요청: {}", dto.getEmail());

        boolean verified =
                emailVerificationService.verifyCode(dto.getEmail(), dto.getVerificationCode());

        if (verified) {
            return ResponseEntity.ok(AuthResponseDto.success("이메일 인증이 완료되었습니다."));
        } else {
            return ResponseEntity.badRequest()
                    .body(AuthResponseDto.fail("인증코드가 올바르지 않거나 만료되었습니다."));
        }
    }

    @GetMapping("/emailCheck")
    public ResponseEntity<AuthResponseDto> emailCheck(@RequestParam @NotBlank @Email String email) {

        log.info("이메일 중복 확인 요청: {}", email);

        boolean duplicate = formAuthService.emailCheck(email);

        if (duplicate) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(AuthResponseDto.fail("이미 사용 중인 이메일입니다."));
        } else {
            return ResponseEntity.ok(AuthResponseDto.success("사용 가능한 이메일입니다."));
        }
    }

    @PostMapping("/passwordReset")
    public ResponseEntity<AuthResponseDto> resetPassword(
            @Valid @RequestBody PasswordResetRequestDto dto) {
        log.info("비밀번호 재설정 요청: {}", dto.getEmail());

        boolean verified = emailVerificationService.verifyCode(dto.getEmail(), dto.getCode());

        if (!verified) {
            return ResponseEntity.badRequest()
                    .body(AuthResponseDto.fail("인증코드가 올바르지 않거나 만료되었습니다."));
        }

        formAuthService.resetPassword(dto.getEmail(), dto.getNewPassword());

        return ResponseEntity.ok(AuthResponseDto.success("비밀번호가 재설정되었습니다."));
    }

    @PostMapping("/logout")
    public ResponseEntity<AuthResponseDto> logout(Authentication authentication) {

        log.info("로그아웃 요청");

        MembersDetails membersDetails = (MembersDetails) authentication.getPrincipal();
        Long memberId = membersDetails.getId();

        Optional<RefreshToken> refreshTokenOptional = jwtTokenProvider.findRefreshToken(memberId);

        if (refreshTokenOptional.isPresent()) {
            RefreshToken refreshToken = refreshTokenOptional.get();
            tokenRepository.addBlackList(refreshToken);
        }

        return ResponseEntity.ok(AuthResponseDto.success("로그아웃이 완료되었습니다."));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponseDto> refresh(
            @RequestHeader("Authorization") String authorization) {
        log.info("토큰 갱신 요청");

        try {
            String refreshToken = jwtTokenProvider.extractTokenFromHeader(authorization);
            String newAccessToken = jwtTokenProvider.refreshAccessToken(refreshToken);

            return ResponseEntity.ok(AuthResponseDto.success("토큰 갱신이 완료되었습니다.", newAccessToken));

        } catch (JwtAuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(AuthResponseDto.fail(e.getMessage()));
        } catch (Exception e) {
            log.error("토큰 갱신 처리 중 오류 발생", e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(AuthResponseDto.fail("토큰 갱신에 실패했습니다."));
        }
    }
}
