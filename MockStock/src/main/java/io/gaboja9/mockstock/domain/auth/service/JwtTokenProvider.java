package io.gaboja9.mockstock.domain.auth.service;

import io.gaboja9.mockstock.domain.auth.dto.TokenBody;
import io.gaboja9.mockstock.domain.auth.dto.TokenPair;
import io.gaboja9.mockstock.domain.auth.entity.RefreshToken;
import io.gaboja9.mockstock.domain.auth.exception.JwtAuthenticationException;
import io.gaboja9.mockstock.domain.auth.repository.RefreshTokenRepository;
import io.gaboja9.mockstock.domain.auth.repository.TokenRepository;
import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.members.enums.Role;
import io.gaboja9.mockstock.global.config.JwtConfiguration;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import jakarta.transaction.Transactional;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;

import javax.crypto.SecretKey;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class JwtTokenProvider {
    private final JwtConfiguration jwtConfiguration;
    private final RefreshTokenRepository refreshTokenRepository;

    private final TokenRepository tokenRepository;

    public TokenPair generateTokenPair(Members members) {

        String acceessToken = issueAcceessToken(members.getId(), members.getRole());
        String refreshToken = issueRefreshToken(members.getId(), members.getRole());

        tokenRepository.save(members, refreshToken);

        return TokenPair.builder().accessToken(acceessToken).refreshToken(refreshToken).build();
    }

    public Optional<RefreshToken> findRefreshToken(Long membersId) {

        return tokenRepository.findValidRefreshToken(membersId);
    }

    public String issueAcceessToken(Long id, Role role) {
        return issue(id, role, jwtConfiguration.getValidation().getAccess());
    }

    public String issueRefreshToken(Long id, Role role) {
        return issue(id, role, jwtConfiguration.getValidation().getRefresh());
    }

    private String issue(Long id, Role role, Long expTime) {

        return Jwts.builder()
                .subject(id.toString())
                .claim("role", role)
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + expTime))
                .signWith(getSecretKey(), Jwts.SIG.HS256)
                .compact();
    }

    public boolean validate(String token) {
        try {
            Jwts.parser().verifyWith(getSecretKey()).build().parseClaimsJws(token);
            return true;

        } catch (ExpiredJwtException e) {
            throw JwtAuthenticationException.expired();
        } catch (MalformedJwtException e) {
            throw JwtAuthenticationException.malformed();
        } catch (SignatureException e) {
            throw JwtAuthenticationException.invalidSignature();
        } catch (UnsupportedJwtException e) {
            throw JwtAuthenticationException.unsupported();
        } catch (IllegalArgumentException e) {
            throw JwtAuthenticationException.invalid();
        } catch (Exception e) {
            log.error("JWT 검증 중 알 수 없는 오류입니다.", e);
            throw JwtAuthenticationException.invalid();
        }
    }

    public TokenBody parseJwt(String token) {
        Jws<Claims> parsed = Jwts.parser().verifyWith(getSecretKey()).build().parseClaimsJws(token);

        String sub = parsed.getPayload().getSubject();
        String role = parsed.getPayload().get("role").toString();

        return new TokenBody(Long.parseLong(sub), Role.valueOf(role));
    }

    @NotNull
    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(jwtConfiguration.getSecrets().getAppKey().getBytes());
    }

    public String refreshAccessToken(String refreshToken) {
        if (!validate(refreshToken)) {
            throw JwtAuthenticationException.invalid();
        }

        TokenBody tokenBody = parseJwt(refreshToken);
        Long memberId = tokenBody.getMemberId();

        RefreshToken validRefreshToken =
                tokenRepository
                        .findValidRefreshToken(memberId)
                        .orElseThrow(
                                () -> {
                                    log.warn(
                                            "사용자 ID {}의 유효한 RefreshToken을 찾을 수 없음 (블랙리스트 포함)",
                                            memberId);
                                    return JwtAuthenticationException.invalid();
                                });

        if (!validRefreshToken.getRefreshToken().equals(refreshToken)) {
            log.warn("사용자 ID {}의 RefreshToken이 DB와 일치하지 않음", memberId);
            throw JwtAuthenticationException.invalid();
        }

        String newAccessToken = issueAcceessToken(memberId, tokenBody.getRole());
        log.info("사용자 ID {}의 AccessToken 갱신 완료", memberId);

        return newAccessToken;
    }

    public String extractTokenFromHeader(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new IllegalArgumentException("잘못된 인증 헤더");
        }
        return authorization.substring(7);
    }
}
