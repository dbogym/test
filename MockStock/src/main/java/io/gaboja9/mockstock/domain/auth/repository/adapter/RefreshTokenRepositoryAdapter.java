package io.gaboja9.mockstock.domain.auth.repository.adapter;

import io.gaboja9.mockstock.domain.auth.entity.RefreshToken;
import io.gaboja9.mockstock.domain.auth.entity.RefreshTokenBlackList;
import io.gaboja9.mockstock.domain.auth.repository.RefreshTokenBlackListRepository;
import io.gaboja9.mockstock.domain.auth.repository.RefreshTokenRepository;
import io.gaboja9.mockstock.domain.auth.repository.TokenRepository;
import io.gaboja9.mockstock.domain.members.entity.Members;

import jakarta.persistence.EntityManager;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class RefreshTokenRepositoryAdapter implements TokenRepository {

    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenBlackListRepository refreshTokenBlackListRepository;

    private final EntityManager entityManager;

    @Override
    public RefreshToken save(Members members, String token) {
        return refreshTokenRepository.save(
                RefreshToken.builder().members(members).refreshToken(token).build());
    }

    @Override
    public RefreshTokenBlackList addBlackList(RefreshToken refreshToken) {
        return refreshTokenBlackListRepository.save(
                RefreshTokenBlackList.builder().refreshToken(refreshToken).build());
    }

    @Override
    public Optional<RefreshToken> findValidRefreshToken(Long membersId) {

        // refreshToken 조회 (단, 블랙리스트에 토큰 등록 X)
        String jpql =
                """
                    select rf from RefreshToken rf
                    left join RefreshTokenBlackList rtb on rtb.refreshToken = rf
                    where rf.members.id = :membersId and rtb.id is null
                """;

        return entityManager
                .createQuery(jpql, RefreshToken.class)
                .setParameter("membersId", membersId)
                .getResultStream()
                .findFirst();
    }
}
