package io.gaboja9.mockstock.domain.auth.repository;

import io.gaboja9.mockstock.domain.auth.entity.EmailVerification;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Optional;

public interface EmailVerificationRepository extends JpaRepository<EmailVerification, Long> {

    // 미인증 상태의 인증 정보 조회
    Optional<EmailVerification> findByEmailAndVerificationCodeAndVerifiedFalse(
            String email, String verificationCode);

    // 특정 이메일이 최근 인증 요청 조회
    Optional<EmailVerification> findTopByEmailOrderByCreatedAtDesc(String email);

    // 특정 이메일의 인증 완료 여부 확인
    boolean existsByEmailAndVerifiedTrue(String email);

    // 만료된 인증 데이터 삭제
    @Query("DELETE FROM EmailVerification e WHERE e.expiredAt < :now")
    void deleteExpiredVerifications(@Param("now") LocalDateTime now);
}
