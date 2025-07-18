package io.gaboja9.mockstock.domain.auth.controller;

import io.gaboja9.mockstock.domain.auth.dto.TokenBody;
import io.gaboja9.mockstock.domain.auth.dto.TokenPair;
import io.gaboja9.mockstock.domain.auth.dto.request.EmailVerificationRequestDto;
import io.gaboja9.mockstock.domain.auth.dto.request.LoginRequestDto;
import io.gaboja9.mockstock.domain.auth.dto.request.SignUpRequestDto;
import io.gaboja9.mockstock.domain.auth.dto.response.AuthResponseDto;
import io.gaboja9.mockstock.domain.auth.entity.RefreshToken;
import io.gaboja9.mockstock.domain.auth.repository.TokenRepository;
import io.gaboja9.mockstock.domain.auth.service.EmailVerificationService;
import io.gaboja9.mockstock.domain.auth.service.FormAuthService;

import io.gaboja9.mockstock.domain.auth.service.JwtTokenProvider;
import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.members.repository.MembersRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
            @RequestParam @NotBlank @Email String email,
            @RequestParam @NotBlank String verificationCode) {

        log.info("이메일 인증 요청: {}", email);

        boolean verified = emailVerificationService.verifyCode(email, verificationCode);

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
            return ResponseEntity.ok(AuthResponseDto.success("이미 사용 중인 이메일입니다.", true));
        } else {
            return ResponseEntity.ok(AuthResponseDto.success("사용 가능한 이메일입니다.", false));
        }
    }

    @PostMapping("/passwordReset")
    public ResponseEntity<AuthResponseDto> resetPassword(
            @RequestParam @NotBlank @Email String email,
            @RequestParam @NotBlank String code,
            @RequestParam @NotBlank String newPassword) {

        log.info("비밀번호 재설정 요청: {}", email);

        boolean verified = emailVerificationService.verifyCode(email, code);

        if (!verified) {
            return ResponseEntity.badRequest()
                    .body(AuthResponseDto.fail("인증코드가 올바르지 않거나 만료되었습니다."));
        }

        formAuthService.resetPassword(email, newPassword);

        return ResponseEntity.ok(AuthResponseDto.success("비밀번호가 재설정되었습니다."));
    }

    @PostMapping("/logout")
    public ResponseEntity<AuthResponseDto> logout(
            @RequestHeader("Authorization") String authorization) {

        log.info("로그아웃 요청");

        try {
            String accessToken = authorization.replace("Bearer ", "");

            if (!jwtTokenProvider.validate(accessToken)) {
                return ResponseEntity.badRequest().body(AuthResponseDto.fail("유효하지 않은 토큰입니다."));
            }

            TokenBody tokenBody = jwtTokenProvider.parseJwt(accessToken);
            Long memberId = tokenBody.getMemberId();

            Optional<RefreshToken> refreshTokenOptional =
                    jwtTokenProvider.findRefreshToken(memberId);

            if (refreshTokenOptional.isPresent()) {
                RefreshToken refreshToken = refreshTokenOptional.get();
                tokenRepository.addBlackList(refreshToken);
            }

            return ResponseEntity.ok(AuthResponseDto.success("로그아웃이 완료되었습니다."));

        } catch (Exception e) {
            log.error("로그아웃 처리 중 오류 발생", e);
            return ResponseEntity.badRequest().body(AuthResponseDto.fail("로그아웃 처리에 실패했습니다."));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponseDto> refresh(
            @RequestHeader("Authorization") String authorization) {
        log.info("토큰 갱신 요청");

        try {
            String refreshToken = authorization.replace("Bearer ", "");

            if (!jwtTokenProvider.validate(refreshToken)) {
                log.info("유효하지 않은 RefreshToken으로 갱신 시도");

                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(AuthResponseDto.fail("유효하지 않은 RefreshToken입니다."));
            }

            TokenBody tokenBody = jwtTokenProvider.parseJwt(refreshToken);
            Long memberId = tokenBody.getMemberId();

            Optional<RefreshToken> validRefreshTokenOptional =
                    jwtTokenProvider.findRefreshToken(memberId);

            if (validRefreshTokenOptional.isEmpty()) {
                log.warn("사용자 ID {}의 유효한 RefreshToken을 찾을 수 없음 (블랙리스트 포함)", memberId);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(AuthResponseDto.fail("유효한 RefreshToken을 찾을 수 없습니다."));
            }

            RefreshToken validRefreshToken = validRefreshTokenOptional.get();
            if (!validRefreshToken.getRefreshToken().equals(refreshToken)) {
                log.warn("사용자 ID {}의 RefreshToken이 DB와 일치하지 않음", memberId);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(AuthResponseDto.fail("RefreshToken이 일치하지 않습니다."));
            }

            String newAccessToken =
                    jwtTokenProvider.issueAcceessToken(memberId, tokenBody.getRole());

            log.info("사용자 ID {}의 AccessToken 갱신 완료", memberId);

            return ResponseEntity.ok(AuthResponseDto.success("토큰 갱신이 완료되었습니다.", newAccessToken));
        } catch (Exception e) {
            log.error("토큰 갱신 처리 중 오류 발생", e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(AuthResponseDto.fail("토큰 갱신에 실패했습니다."));
        }
    }
}
