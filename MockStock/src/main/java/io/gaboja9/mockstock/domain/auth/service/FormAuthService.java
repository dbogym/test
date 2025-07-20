package io.gaboja9.mockstock.domain.auth.service;

import io.gaboja9.mockstock.domain.auth.dto.TokenPair;
import io.gaboja9.mockstock.domain.auth.dto.request.LoginRequestDto;
import io.gaboja9.mockstock.domain.auth.dto.request.SignUpRequestDto;
import io.gaboja9.mockstock.domain.auth.exception.AuthException;
import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.members.enums.Role;
import io.gaboja9.mockstock.domain.members.repository.MembersRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class FormAuthService {
    private final MembersRepository membersRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailVerificationService emailVerificationService;
    private final JwtTokenProvider jwtTokenProvider;

    // form 회원가입
    public void signUp(SignUpRequestDto dto) {

        // 이메일 중복 확인
        if (emailCheck(dto.getEmail())) {
            throw AuthException.emailAlreadyExists();
        }

        // 인증코드 확인
        if (!emailVerificationService.verifyCode(dto.getEmail(), dto.getVerificationCode())) {
            throw AuthException.invalidVerificationCode();
        }

        // 비밀번호 확인
        if (!dto.getPassword().equals(dto.getPasswordConfirm())) {
            throw AuthException.passwordMismatch();
        }

        String encodedPassword = passwordEncoder.encode(dto.getPassword());

        Members member =
                Members.builder()
                        .nickname(dto.getName())
                        .email(dto.getEmail())
                        .password(encodedPassword)
                        .role(Role.MEMBER)
                        .profileImage(null)
                        .provider("LOCAL")
                        .cashBalance(30000000)
                        .bankruptcyCnt(0)
                        .build();

        membersRepository.save(member);
        log.info("회원가입 완료: {}", dto.getEmail());
    }

    // form 로그인
    @Transactional
    public TokenPair login(LoginRequestDto dto) {
        log.info("로그인 시도: {}", dto.getEmail());

        // 이메일로 회원 조회
        Optional<Members> member = membersRepository.findByEmail(dto.getEmail());
        if (member.isEmpty()) {
            throw AuthException.invalidCredentials();
        }

        // LOCAL 사용자인지 확인
        if (!member.get().getProvider().equals("LOCAL")) {
            throw AuthException.socialLoginRequired(member.get().getProvider());
        }

        // 비밀번호 확인
        if (!passwordEncoder.matches(dto.getPassword(), member.get().getPassword())) {
            throw AuthException.passwordMismatch();
        }

        TokenPair tokenPair = jwtTokenProvider.generateTokenPair(member.get());
        log.info("로그인 성공: {}", dto.getEmail());

        return tokenPair;
    }

    // 이메일 중복 확인
    public boolean emailCheck(String email) {
        return membersRepository.findByEmail(email).isPresent();
    }

    // 비밀번호 재설정
    public void resetPassword(String email, String newPassword) {
        Optional<Members> member = membersRepository.findByEmail(email);

        if (!"LOCAL".equals(member.get().getProvider())) {
            throw new IllegalStateException("소셜 로그인 계정은 비밀번호 재설정이 불가능합니다.");
        }

        String encodedPassword = passwordEncoder.encode(newPassword);
        member.get().setPassword(encodedPassword);

        log.info("비밀번호 재설정 완료: {}", email);
    }
}
