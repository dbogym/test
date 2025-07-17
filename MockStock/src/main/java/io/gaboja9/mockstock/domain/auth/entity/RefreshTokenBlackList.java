package io.gaboja9.mockstock.domain.auth.entity;

import io.gaboja9.mockstock.global.common.BaseEntity;

import jakarta.persistence.*;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshTokenBlackList extends BaseEntity {

    @Id
    @Column(name = "refresh_token_black_list_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "refresh_token_id")
    private RefreshToken refreshToken;

    @Builder
    public RefreshTokenBlackList(RefreshToken refreshToken) {
        this.refreshToken = refreshToken;
    }
}
