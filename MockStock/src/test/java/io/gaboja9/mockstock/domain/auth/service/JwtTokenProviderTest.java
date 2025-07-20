package io.gaboja9.mockstock.domain.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.gaboja9.mockstock.domain.auth.dto.TokenBody;
import io.gaboja9.mockstock.domain.auth.dto.TokenPair;
import io.gaboja9.mockstock.domain.auth.entity.RefreshToken;
import io.gaboja9.mockstock.domain.auth.exception.JwtAuthenticationException;
import io.gaboja9.mockstock.domain.auth.repository.RefreshTokenRepository;
import io.gaboja9.mockstock.domain.auth.repository.TokenRepository;
import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.members.enums.Role;
import io.gaboja9.mockstock.global.config.JwtConfiguration;
import io.gaboja9.mockstock.global.exception.ErrorCode;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class JwtTokenProviderTest {

    @Mock private JwtConfiguration jwtConfiguration;

    @Mock private JwtConfiguration.Validation validation;

    @Mock private JwtConfiguration.Secrets secrets;

    @Mock private TokenRepository tokenRepository;

    @Mock private RefreshTokenRepository refreshTokenRepository;

    @InjectMocks private JwtTokenProvider jwtTokenProvider;

    private Members testMember;
    private final String TEST_SECRET_KEY = "testSecretKeyForJwtTokenProviderTestMustBeLongEnough";

    @BeforeEach
    void setUp() {
        testMember =
                new Members(
                        1L,
                        "test@example.com",
                        "testUser",
                        "LOCAL",
                        "test.png",
                        30000000,
                        0,
                        LocalDateTime.now());

        when(jwtConfiguration.getValidation()).thenReturn(validation);
        when(jwtConfiguration.getSecrets()).thenReturn(secrets);
        when(secrets.getAppKey()).thenReturn(TEST_SECRET_KEY);
    }

    // 1. 토큰 생성 테스트
    @Test
    void generateTokenPair_정상적인_토큰페어_생성() {
        // given
        when(validation.getAccess()).thenReturn(600000L);
        when(validation.getRefresh()).thenReturn(86400000L);

        RefreshToken savedRefreshToken =
                RefreshToken.builder()
                        .refreshToken("mocked-refresh-token")
                        .members(testMember)
                        .build();

        when(tokenRepository.save(eq(testMember), anyString())).thenReturn(savedRefreshToken);

        // when
        TokenPair result = jwtTokenProvider.generateTokenPair(testMember);

        // 로그
        System.out.println("AccessToken: " + result.getAccessToken());
        System.out.println("RefreshToken: " + result.getRefreshToken());

        // then
        assertThat(result).isNotNull();
        assertThat(result.getAccessToken()).isNotNull();
        assertThat(result.getRefreshToken()).isNotNull();

        // JWT 형식 확인 (3개 부분으로 나뉘어짐)
        assertThat(result.getAccessToken().split("\\.")).hasSize(3);
        assertThat(result.getRefreshToken().split("\\.")).hasSize(3);

        verify(tokenRepository).save(eq(testMember), anyString());
    }

    @Test
    void issueAcceessToken_정상적인_액세스토큰_생성() {
        // given
        when(validation.getAccess()).thenReturn(600000L);

        Long memberId = 1L;
        Role adminRole = Role.ADMIN;
        Role memberRole = Role.MEMBER;

        // when
        String adminToken = jwtTokenProvider.issueAcceessToken(memberId, adminRole);
        String memberToken = jwtTokenProvider.issueAcceessToken(memberId, memberRole);

        // then
        TokenBody adminTokenBody = jwtTokenProvider.parseJwt(adminToken);
        TokenBody memberTokenBody = jwtTokenProvider.parseJwt(memberToken);

        assertThat(adminTokenBody.getRole()).isEqualTo(adminRole);
        assertThat(memberTokenBody.getRole()).isEqualTo(memberRole);

        // 로그
        System.out.println("adminToken = " + adminToken);
        System.out.println("memberToken = " + memberToken);
        System.out.println("adminTokenBody = " + adminTokenBody);
        System.out.println("memberTokenBody = " + memberTokenBody);
    }

    @Test
    void issueRefreshToken_정상적인_리프레쉬토큰_생성() {
        // given
        when(validation.getRefresh()).thenReturn(86400000L);

        Long memberId = 1L;
        Role adminRole = Role.ADMIN;
        Role memberRole = Role.MEMBER;

        // when
        String adminToken = jwtTokenProvider.issueRefreshToken(memberId, adminRole);
        String memberToken = jwtTokenProvider.issueRefreshToken(memberId, memberRole);

        // then
        TokenBody adminTokenBody = jwtTokenProvider.parseJwt(adminToken);
        TokenBody memberTokenBody = jwtTokenProvider.parseJwt(memberToken);

        assertThat(adminTokenBody.getRole()).isEqualTo(adminRole);
        assertThat(memberTokenBody.getRole()).isEqualTo(memberRole);

        System.out.println("adminToken = " + adminToken);
        System.out.println("memberToken = " + memberToken);
        System.out.println("adminTokenBody = " + adminTokenBody);
        System.out.println("memberTokenBody = " + memberTokenBody);
    }

    // 2. 토큰 검증 테스트
    @Test
    void validate_유효한_토큰_검증_성공() {
        // given
        when(validation.getAccess()).thenReturn(600000L);
        when(validation.getRefresh()).thenReturn(86400000L);

        Long memberId = 1L;
        Role role = Role.MEMBER;

        String acceessToken = jwtTokenProvider.issueAcceessToken(memberId, role);
        String refreshToken = jwtTokenProvider.issueRefreshToken(memberId, role);

        // when
        boolean accessTokenValidate = jwtTokenProvider.validate(acceessToken);
        boolean refreshTokenValidate = jwtTokenProvider.validate(refreshToken);

        // then
        assertThat(accessTokenValidate).isTrue();
        assertThat(refreshTokenValidate).isTrue();
    }

    @Test
    void validate_만료된_토큰_예외발생() {
        // given
        when(validation.getAccess()).thenReturn(1L);

        Long memberId = 1L;
        Role role = Role.MEMBER;

        String expiredToken = jwtTokenProvider.issueAcceessToken(memberId, role);

        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // when & then
        assertThatThrownBy(() -> jwtTokenProvider.validate(expiredToken))
                .isInstanceOf(JwtAuthenticationException.class)
                .hasMessage(ErrorCode.JWT_TOKEN_EXPIRED.getMessage());
    }

    @Test
    void validate_잘못된_형식_토큰_예외발생() {
        // given
        String malformedToken = "malformed.token";

        // when & then
        assertThatThrownBy(() -> jwtTokenProvider.validate(malformedToken))
                .isInstanceOf(JwtAuthenticationException.class)
                .hasMessage(ErrorCode.JWT_TOKEN_MALFORMED.getMessage());
    }

    @Test
    void validate_잘못된_서명_토큰_예외발생() {
        // given
        String acceessToken = jwtTokenProvider.issueAcceessToken(1L, Role.MEMBER);

        String[] parts = acceessToken.split("\\.");
        String invalidSignatureToken = parts[0] + "." + parts[1] + ".invalidSignature";

        // when & then
        assertThatThrownBy(() -> jwtTokenProvider.validate(invalidSignatureToken))
                .isInstanceOf(JwtAuthenticationException.class)
                .hasMessage(ErrorCode.JWT_SIGNATURE_INVALID.getMessage());
    }

    @Test
    void validate_지원되지_않는_토큰_예외발생() {
        // given: alg가 none인 토큰을 수동으로 생성
        String header =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes());

        String payload =
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString("{\"sub\":\"1\",\"role\":\"MEMBER\"}".getBytes());

        String unsupportedToken = header + "." + payload + ".";

        // when & then
        assertThatThrownBy(() -> jwtTokenProvider.validate(unsupportedToken))
                .isInstanceOf(JwtAuthenticationException.class)
                .hasMessage(ErrorCode.JWT_TOKEN_UNSUPPORTED.getMessage());
    }

    @Test
    void validate_IllegalArgumentException_예외발생() {
        // given
        String nullToken = null;

        // when & then
        assertThatThrownBy(() -> jwtTokenProvider.validate(nullToken))
                .isInstanceOf(JwtAuthenticationException.class)
                .hasMessage(ErrorCode.JWT_TOKEN_INVALID.getMessage());
    }

    // 3. 토큰 파싱 테스트
    @Test
    void parseJwt_정상적인_파싱_성공() {
        // given
        when(validation.getAccess()).thenReturn(600000L);

        Long memberId = 1L;
        Role memberRole = Role.MEMBER;

        String acceessToken = jwtTokenProvider.issueAcceessToken(memberId, memberRole);

        // when
        TokenBody result = jwtTokenProvider.parseJwt(acceessToken);

        // then
        assertThat(result.getMemberId()).isEqualTo(1L);
        assertThat(result.getRole()).isEqualTo(Role.MEMBER);
    }

    // 4. RefreshToken으로 AccessToken 갱신 테스트
    @Test
    void refreshAccessToken_정상_갱신_성공() {
        // given
        when(validation.getAccess()).thenReturn(600000L);
        when(validation.getRefresh()).thenReturn(86400000L);

        Long memberId = 1L;
        Role role = Role.MEMBER;

        String refreshToken = jwtTokenProvider.issueRefreshToken(memberId, role);

        RefreshToken validRefreshToken =
                RefreshToken.builder().refreshToken(refreshToken).members(testMember).build();

        when(tokenRepository.findValidRefreshToken(memberId))
                .thenReturn(Optional.of(validRefreshToken));

        // when
        String newAccessToken = jwtTokenProvider.refreshAccessToken(refreshToken);

        // then
        assertThat(newAccessToken).isNotNull();
        assertThat(newAccessToken.split("\\.")).hasSize(3);

        TokenBody tokenBody = jwtTokenProvider.parseJwt(newAccessToken);
        assertThat(tokenBody.getMemberId()).isEqualTo(memberId);
        assertThat(tokenBody.getRole()).isEqualTo(role);
    }

    @Test
    void refreshAccessToken_유효하지_않은_토큰_예외발생() {
        // given
        String invalidToken = "invalid.token.format";

        // when & then
        assertThatThrownBy(() -> jwtTokenProvider.refreshAccessToken(invalidToken))
                .isInstanceOf(JwtAuthenticationException.class);
    }

    @Test
    void refreshAccessToken_DB에_토큰_없음_예외발생() {
        // given
        when(validation.getRefresh()).thenReturn(86400000L);

        String refreshToken = jwtTokenProvider.issueRefreshToken(1L, Role.MEMBER);
        when(tokenRepository.findValidRefreshToken(1L)).thenReturn(Optional.empty());

        // when & then
        assertThatThrownBy(() -> jwtTokenProvider.refreshAccessToken(refreshToken))
                .isInstanceOf(JwtAuthenticationException.class);
    }

    // 5. 토큰 추출 테스트
    @Test
    void extractTokenFromHeader_정상_추출_성공() {
        // given
        String token = "eyJhbGciOiJIUzI1NiJ9.test.token";
        String authorization = "Bearer " + token;

        // when
        String result = jwtTokenProvider.extractTokenFromHeader(authorization);

        // then
        assertThat(result).isEqualTo(token);
    }

    @Test
    void extractTokenFromHeader_Bearer_없음_예외발생() {
        // given
        String authorization = "InvalidHeader eyJhbGciOiJIUzI1NiJ9.test.token";

        // when & then
        assertThatThrownBy(() -> jwtTokenProvider.extractTokenFromHeader(authorization))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("잘못된 인증 헤더");
    }

    @Test
    void extractTokenFromHeader_null_헤더_예외발생() {
        // given
        String authorization = null;

        // when & then
        assertThatThrownBy(() -> jwtTokenProvider.extractTokenFromHeader(authorization))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("잘못된 인증 헤더");
    }
}
