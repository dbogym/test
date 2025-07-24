package io.gaboja9.mockstock.domain.auth.entity;

import io.gaboja9.mockstock.global.common.BaseEntity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;

import lombok.*;

import java.time.LocalDateTime;

@Getter
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class EmailVerification extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    @Email
    private String email;

    @Column(nullable = false)
    private String verificationCode;

    @Setter private boolean verified = false;

    @Column(nullable = false)
    private LocalDateTime expiredAt;

    @Builder
    public EmailVerification(String email, String verificationCode, LocalDateTime expiredAt) {
        this.email = email;
        this.verificationCode = verificationCode;
        this.expiredAt = expiredAt;
    }

    public boolean expired() {
        return LocalDateTime.now().isAfter(this.expiredAt);
    }

    public void verify() {
        this.verified = true;
    }
}
