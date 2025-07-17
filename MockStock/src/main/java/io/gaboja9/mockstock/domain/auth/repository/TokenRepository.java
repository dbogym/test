package io.gaboja9.mockstock.domain.auth.repository;

import io.gaboja9.mockstock.domain.auth.entity.RefreshToken;
import io.gaboja9.mockstock.domain.auth.entity.RefreshTokenBlackList;
import io.gaboja9.mockstock.domain.members.entity.Members;

import java.util.Optional;

public interface TokenRepository {
    RefreshToken save(Members members, String token);

    RefreshTokenBlackList addBlackList(RefreshToken refreshToken);

    Optional<RefreshToken> findValidRefreshToken(Long memberId);
}
