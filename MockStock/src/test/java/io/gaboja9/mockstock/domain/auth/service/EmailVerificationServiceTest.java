package io.gaboja9.mockstock.domain.auth.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import io.gaboja9.mockstock.domain.auth.entity.EmailVerification;
import io.gaboja9.mockstock.domain.auth.exception.AuthException;
import io.gaboja9.mockstock.domain.auth.repository.EmailVerificationRepository;
import io.gaboja9.mockstock.domain.members.repository.MembersRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Optional;

class EmailVerificationServiceTest {
    private EmailVerificationRepository emailVerificationRepository;
    private MembersRepository membersRepository;
    private EmailVerificationService emailVerificationService;

    @BeforeEach
    void setUp() {
        emailVerificationRepository = mock(EmailVerificationRepository.class);
        membersRepository = mock(MembersRepository.class);
        emailVerificationService =
                new EmailVerificationService(emailVerificationRepository, membersRepository);
    }

    @Test
    void checkResendCooldown_쿨다운이내_예외발생() {
        // given
        String email = "test@example.com";
        String code = "123456";

        EmailVerification verification =
                EmailVerification.builder()
                        .email(email)
                        .verificationCode(code)
                        .expiredAt(LocalDateTime.now().plusMinutes(10))
                        .build();

        verification.setCreatedAt(LocalDateTime.now().minusSeconds(30)); // 30초 전에 보냄

        when(emailVerificationRepository.findTopByEmailOrderByCreatedAtDesc(email))
                .thenReturn(Optional.of(verification));

        // when & then
        AuthException ex =
                assertThrows(
                        AuthException.class,
                        () ->
                                emailVerificationService.sendVerificationCode(
                                        email)); // 내부적으로 checkResendCooldown() 호출해야 함

        assertTrue(ex.getMessage().contains("초 후에 재발송"));
    }

    @Test
    void checkResendCooldown_쿨다운후_예외없음() {
        // given
        String email = "test@example.com";
        String code = "123456";

        EmailVerification verification =
                EmailVerification.builder()
                        .email(email)
                        .verificationCode(code)
                        .expiredAt(LocalDateTime.now().plusMinutes(10))
                        .build();

        verification.setCreatedAt(LocalDateTime.now().minusMinutes(2)); // 2분 전에 보냄 (1분 쿨다운 지남)

        when(emailVerificationRepository.findTopByEmailOrderByCreatedAtDesc(email))
                .thenReturn(Optional.of(verification));
        when(membersRepository.findByEmail(email)).thenReturn(Optional.empty());

        // when & then
        assertDoesNotThrow(() -> emailVerificationService.sendVerificationCode(email));
    }
}
