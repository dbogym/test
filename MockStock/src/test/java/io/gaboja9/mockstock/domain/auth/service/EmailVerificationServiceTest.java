package io.gaboja9.mockstock.domain.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

import io.gaboja9.mockstock.domain.auth.entity.EmailVerification;
import io.gaboja9.mockstock.domain.auth.exception.AuthException;
import io.gaboja9.mockstock.domain.auth.repository.EmailVerificationRepository;
import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.members.repository.MembersRepository;
import io.gaboja9.mockstock.global.exception.ErrorCode;

import jakarta.mail.internet.MimeMessage;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class EmailVerificationServiceTest {
    @Mock private EmailVerificationRepository emailVerificationRepository;

    @Mock private MembersRepository membersRepository;

    @Mock private JavaMailSender mailSender;

    @Mock private MimeMessage mimeMessage;

    @InjectMocks private EmailVerificationService emailVerificationService;

    private final String TEST_EMAIL = "test@example.com";
    private final String EXISTING_EMAIL = "existing@example.com";

    @BeforeEach
    void setUp() {
        when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
    }

    //    1. 인증코드 발송 테스트
    @Test
    void sendVerificationCode_정상적인_발송_성공() {
        // when
        when(membersRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());
        when(emailVerificationRepository.findTopByEmailOrderByCreatedAtDesc(TEST_EMAIL))
                .thenReturn(Optional.empty());

        emailVerificationService.sendVerificationCode(TEST_EMAIL);
        // then
        verify(membersRepository).findByEmail(TEST_EMAIL);
        verify(emailVerificationRepository).save(any(EmailVerification.class));
        verify(mailSender).send(any(MimeMessage.class));
    }

    @Test
    void sendVerificationCode_이메일_중복_예외발생() {
        // given
        Members existingMember =
                new Members(
                        1L,
                        EXISTING_EMAIL,
                        "testUser",
                        "LOCAL",
                        "profile.png",
                        30000000,
                        0,
                        LocalDateTime.now());
        when(membersRepository.findByEmail(EXISTING_EMAIL)).thenReturn(Optional.of(existingMember));

        // when & then
        assertThatThrownBy(() -> emailVerificationService.sendVerificationCode(EXISTING_EMAIL))
                .isInstanceOf(AuthException.class)
                .hasMessage(ErrorCode.EMAIL_ALREADY_EXISTS.getMessage());
        verify(emailVerificationRepository, never()).save(any());
        verify(mailSender, never()).send(any(MimeMessage.class));
    }

    @Test
    void sendVerificationCode_재발송_쿨다운_예외발생() {
        // given
        LocalDateTime recentTime = LocalDateTime.now().minusSeconds(30);
        EmailVerification recentVerification =
                EmailVerification.builder()
                        .email(TEST_EMAIL)
                        .verificationCode("123456")
                        .expiredAt(LocalDateTime.now().plusMinutes(5))
                        .build();

        ReflectionTestUtils.setField(recentVerification, "createdAt", recentTime);

        when(membersRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());
        when(emailVerificationRepository.findTopByEmailOrderByCreatedAtDesc(TEST_EMAIL))
                .thenReturn(Optional.of(recentVerification));

        // when & then
        assertThatThrownBy(() -> emailVerificationService.sendVerificationCode(TEST_EMAIL))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("초 후에 재발송할 수 있습니다.");
    }

    @Test
    void sendVerificationCode_쿨다운_시간_지난_후_재발송_성공() {
        // given
        LocalDateTime oldTime = LocalDateTime.now().minusMinutes(2);
        EmailVerification oldVerification =
                EmailVerification.builder()
                        .email(TEST_EMAIL)
                        .verificationCode("123456")
                        .expiredAt(LocalDateTime.now().plusMinutes(5))
                        .build();

        ReflectionTestUtils.setField(oldVerification, "createdAt", oldTime);

        when(membersRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());
        when(emailVerificationRepository.findTopByEmailOrderByCreatedAtDesc(TEST_EMAIL))
                .thenReturn(Optional.of(oldVerification));

        // when
        emailVerificationService.sendVerificationCode(TEST_EMAIL);

        // then
        verify(emailVerificationRepository).save(any(EmailVerification.class));
        verify(mailSender).send(any(MimeMessage.class));
    }

    //    2. 인증코드 검증 테스트
    @Test
    void verifyCode_정상적인_검증_성공() {
        // given
        String email = TEST_EMAIL;
        String verificationCode = "123456";

        EmailVerification emailVerification =
                EmailVerification.builder()
                        .email(email)
                        .verificationCode(verificationCode)
                        .expiredAt(LocalDateTime.now().plusMinutes(5))
                        .build();

        when(emailVerificationRepository.findByEmailAndVerificationCodeAndVerifiedFalse(
                        email, verificationCode))
                .thenReturn(Optional.of(emailVerification));

        // when
        boolean result = emailVerificationService.verifyCode(email, verificationCode);

        // then
        assertThat(result).isTrue();
        assertThat(emailVerification.isVerified()).isTrue();
        verify(emailVerificationRepository).save(emailVerification);
    }

    @Test
    void verifyCode_잘못된_이메일_or_잘못된_인증코드_or_이미_검증되어_실패() {
        // given
        String email = TEST_EMAIL;
        String wrongCode = "999999";

        when(emailVerificationRepository.findByEmailAndVerificationCodeAndVerifiedFalse(
                        email, wrongCode))
                .thenReturn(Optional.empty());

        // when
        boolean result = emailVerificationService.verifyCode(email, wrongCode);

        // then
        assertThat(result).isFalse();
        verify(emailVerificationRepository, never()).save(any());
    }

    @Test
    void verifyCode_만료된_인증코드_실패() {
        // given
        String email = TEST_EMAIL;
        String verificationCode = "123456";

        EmailVerification expiredVerification =
                EmailVerification.builder()
                        .email(email)
                        .verificationCode(verificationCode)
                        .expiredAt(LocalDateTime.now().minusMinutes(1))
                        .build();

        when(emailVerificationRepository.findByEmailAndVerificationCodeAndVerifiedFalse(
                        email, verificationCode))
                .thenReturn(Optional.of(expiredVerification));

        // when
        boolean result = emailVerificationService.verifyCode(email, verificationCode);

        // then
        assertThat(result).isFalse();
        assertThat(expiredVerification.isVerified()).isFalse();
        verify(emailVerificationRepository, never()).save(any());
    }

    // 3. 이메일 인증 완료 여부
    @Test
    void emailVerified_인증_완료된_이메일_true_반환() {
        // given
        String email = TEST_EMAIL;
        when(emailVerificationRepository.existsByEmailAndVerifiedTrue(email)).thenReturn(true);

        // when
        boolean result = emailVerificationService.emailVerified(email);

        // then
        assertThat(result).isTrue();
        verify(emailVerificationRepository).existsByEmailAndVerifiedTrue(email);
    }

    @Test
    void emailVerified_미인증_이메일_false_반환() {
        // given
        String email = TEST_EMAIL;
        when(emailVerificationRepository.existsByEmailAndVerifiedTrue(email)).thenReturn(false);

        // when
        boolean result = emailVerificationService.emailVerified(email);

        // then
        assertThat(result).isFalse();
        verify(emailVerificationRepository).existsByEmailAndVerifiedTrue(email);
    }

    @Test
    void emailVerified_존재하지_않는_이메일_false_반환() {
        // given
        String nonExistentEmail = "nonexistent@example.com";
        when(emailVerificationRepository.existsByEmailAndVerifiedTrue(nonExistentEmail))
                .thenReturn(false);

        // when
        boolean result = emailVerificationService.emailVerified(nonExistentEmail);

        // then
        assertThat(result).isFalse();
        verify(emailVerificationRepository).existsByEmailAndVerifiedTrue(nonExistentEmail);
    }

    // 4. 만료된 정리 테스트
    @Test
    void cleanupExpiredVerifications_만료된_데이터_정리() {
        // given
        LocalDateTime now = LocalDateTime.now();

        // when
        emailVerificationService.cleanupExpiredVerifications();

        // then
        verify(emailVerificationRepository).deleteExpiredVerifications(any(LocalDateTime.class));
    }

    @Test
    void cleanupExpiredVerifications_현재시간_기준으로_삭제() {
        // given
        LocalDateTime beforeCall = LocalDateTime.now().minusSeconds(1);

        // when
        emailVerificationService.cleanupExpiredVerifications();

        // then
        ArgumentCaptor<LocalDateTime> timeCaptor = ArgumentCaptor.forClass(LocalDateTime.class);
        verify(emailVerificationRepository).deleteExpiredVerifications(timeCaptor.capture());

        LocalDateTime capturedTime = timeCaptor.getValue();
        LocalDateTime afterCall = LocalDateTime.now().plusSeconds(1);

        assertThat(capturedTime).isBetween(beforeCall, afterCall);
    }
}
