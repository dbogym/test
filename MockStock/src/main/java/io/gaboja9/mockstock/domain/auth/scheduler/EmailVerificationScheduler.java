package io.gaboja9.mockstock.domain.auth.scheduler;

import io.gaboja9.mockstock.domain.auth.service.EmailVerificationService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class EmailVerificationScheduler {
    private final EmailVerificationService emailVerificationService;

    @Scheduled(cron = "0 0 * * * *")
    public void cleanupExpiredVerifications() {
        try {
            emailVerificationService.cleanupExpiredVerifications();
        } catch (Exception e) {
            log.error("만료된 인증 데이터 정리 중 오류 발생", e);
        }
    }
}
