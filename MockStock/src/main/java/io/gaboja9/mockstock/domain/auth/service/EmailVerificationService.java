package io.gaboja9.mockstock.domain.auth.service;

import io.gaboja9.mockstock.domain.auth.entity.EmailVerification;
import io.gaboja9.mockstock.domain.auth.exception.AuthException;
import io.gaboja9.mockstock.domain.auth.repository.EmailVerificationRepository;
import io.gaboja9.mockstock.domain.members.repository.MembersRepository;
import io.gaboja9.mockstock.global.exception.ErrorCode;
import org.springframework.transaction.annotation.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class EmailVerificationService {

    private final EmailVerificationRepository emailVerificationRepository;
    private final MembersRepository membersRepository;

    private static final int VERIFICATION_CODE_LENGTH = 6;
    private static final int VERIFICATION_CODE_EXPIRY_MINUTES = 5;
    private static final int RESEND_COOLDOWN_MINUTES = 1;

    // 이메일 발송
    private void sendEmail(String email, String verificationCode) {
        // TODO: 실제 이메일 발송 로직 구현

        log.info("==이메일 발송==");
        log.info("수신자: {}", email);
        log.info("제목: MockStock 회원가입 인증코드");
        log.info("내용: 인증코드는 [{}]입니다. 5분 내에 입력해주세요.", verificationCode);
    }

    // 인증코드 발송 (재발송도 고려..)
    public void sendVerificationCode(String email) {

        // 이메일 중복 검사
        if( membersRepository.findByEmail(email).isPresent() ) {
            throw AuthException.emailAlreadyExists();
        }

        // 쿨다운 검사
        checkResendCooldown(email);

        // 인증코드 생성
        String VerificationCode = generateVerificationCode();

        // 인증정보 저장
        EmailVerification emailVerification = EmailVerification.builder()
                .email(email)
                .verificationCode(VerificationCode)
                .expiredAt(LocalDateTime.now().plusMinutes(VERIFICATION_CODE_EXPIRY_MINUTES))
                .build();

        emailVerificationRepository.save(emailVerification);

        // 이메일 발송
        sendEmail(email, VerificationCode);
        log.info("인증코드가 {}로 발송되었습니다. 코드: {}",  email, VerificationCode);
    }

    // 인증코드 검증
    @Transactional(readOnly = true)
    public boolean verifyCode(String email, String code) {
        Optional<EmailVerification> verificationOpt =
                emailVerificationRepository.findByEmailAndVerificationCodeAndVerifiedFalse(email, code);

        if( verificationOpt.isEmpty() ) {
            return false;
        }

        EmailVerification verification = verificationOpt.get();

        if(verification.expired()) {
            return false;
        }

        verification.verify();
        emailVerificationRepository.save(verification);

        return true;
    }

    // 인증 완료 여부 확인
    @Transactional
    public boolean emailVerified(String email) {
        return emailVerificationRepository.existsByEmailAndVerifiedTrue(email);
    }

    // 이메일 재발송 쿨다운 검사 (이메일 최근 인증 요청 조회 -> 1분 이내이면 오류 발생)
    private void checkResendCooldown(String email) {
        Optional<EmailVerification> recentVerification =
                emailVerificationRepository.findTopByEmailOrderByCreatedAtDesc(email);

        if ( recentVerification.isPresent() ) {
            LocalDateTime lastSentTime = recentVerification.get().getCreatedAt();
            LocalDateTime now = LocalDateTime.now();
            LocalDateTime cooldownTime = lastSentTime.plusMinutes(RESEND_COOLDOWN_MINUTES);

            if( now.isBefore(cooldownTime) ) {
                long retryAfterSeconds = Duration.between(now, cooldownTime).getSeconds();
                throw AuthException.authResendTooEarly(retryAfterSeconds);
            }
        }
    }

    // 인증코드 생성
    private String generateVerificationCode() {
        Random random = new Random();
        StringBuilder code = new StringBuilder();

        for (int i =0; i<VERIFICATION_CODE_LENGTH; i++) {
            code.append(random.nextInt(10));
        }

        return code.toString();
    }

    // 만료된 인증 데이터 정리
    public void cleanupExpiredVerifications() {
        emailVerificationRepository.deleteExpiredVerifications(LocalDateTime.now());
        log.info("만료된 인증 데이터를 정리했습니다.");
    }
}
