package io.gaboja9.mockstock.domain.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

import io.gaboja9.mockstock.domain.auth.dto.TokenPair;
import io.gaboja9.mockstock.domain.auth.dto.request.LoginRequestDto;
import io.gaboja9.mockstock.domain.auth.dto.request.SignUpRequestDto;
import io.gaboja9.mockstock.domain.auth.exception.AuthException;
import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.members.enums.Role;
import io.gaboja9.mockstock.domain.members.repository.MembersRepository;
import io.gaboja9.mockstock.global.exception.ErrorCode;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;

@ExtendWith(MockitoExtension.class)
class FormAuthServiceTest {
    @Mock private MembersRepository membersRepository;

    @Mock private PasswordEncoder passwordEncoder;

    @Mock private EmailVerificationService emailVerificationService;

    @Mock private JwtTokenProvider jwtTokenProvider;

    @InjectMocks private FormAuthService formAuthService;

    private SignUpRequestDto validSignUpDto;
    private LoginRequestDto validLoginDto;
    private final String TEST_EMAIL = "test@example.com";
    private final String TEST_PASSWORD = "password123!";
    private final String ENCODED_PASSWORD = "encodedPassword123";

    @BeforeEach
    void setUp() {
        validSignUpDto =
                SignUpRequestDto.builder()
                        .name("testUser")
                        .email(TEST_EMAIL)
                        .verificationCode("123456")
                        .password(TEST_PASSWORD)
                        .passwordConfirm(TEST_PASSWORD)
                        .build();

        validLoginDto = LoginRequestDto.builder().email(TEST_EMAIL).password(TEST_PASSWORD).build();
    }

    // 1. 회원가입
    @Test
    void signUp_정상_회원가입_성공() {
        // given
        when(membersRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());
        when(emailVerificationService.verifyCode(TEST_EMAIL, "123456")).thenReturn(true);
        when(passwordEncoder.encode(TEST_PASSWORD)).thenReturn(ENCODED_PASSWORD);

        // when
        formAuthService.signUp(validSignUpDto);

        // then
        verify(membersRepository).findByEmail(TEST_EMAIL);
        verify(emailVerificationService).verifyCode(TEST_EMAIL, "123456");
        verify(passwordEncoder).encode(TEST_PASSWORD);

        ArgumentCaptor<Members> memberCaptor = ArgumentCaptor.forClass(Members.class);
        verify(membersRepository).save(memberCaptor.capture());

        Members savedMember = memberCaptor.getValue();
        assertThat(savedMember.getEmail()).isEqualTo(TEST_EMAIL);
        assertThat(savedMember.getNickname()).isEqualTo("testUser");
        assertThat(savedMember.getPassword()).isEqualTo(ENCODED_PASSWORD);
        assertThat(savedMember.getProvider()).isEqualTo("LOCAL");
        assertThat(savedMember.getRole()).isEqualTo(Role.MEMBER);
        assertThat(savedMember.getCashBalance()).isEqualTo(30000000);
    }

    @Test
    void signUp_이메일_중복_예외발생() {
        // given
        Members existingMember =
                new Members(
                        1L,
                        TEST_EMAIL,
                        "existing",
                        "LOCAL",
                        "profile.png",
                        30000000,
                        0,
                        LocalDateTime.now());
        when(membersRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(existingMember));

        // when & then
        assertThatThrownBy(() -> formAuthService.signUp(validSignUpDto))
                .isInstanceOf(AuthException.class)
                .hasMessage(ErrorCode.EMAIL_ALREADY_EXISTS.getMessage());

        verify(emailVerificationService, never()).verifyCode(any(), any());
        verify(membersRepository, never()).save(any());
    }

    @Test
    void signUp_인증코드_검증_실패_예외발생() {
        // given
        when(membersRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());
        when(emailVerificationService.verifyCode(TEST_EMAIL, "123456")).thenReturn(false);

        // when & then
        assertThatThrownBy(() -> formAuthService.signUp(validSignUpDto))
                .isInstanceOf(AuthException.class)
                .hasMessage(ErrorCode.INVALID_VERIFICATION_CODE.getMessage());

        verify(passwordEncoder, never()).encode(any());
        verify(membersRepository, never()).save(any());
    }

    @Test
    void signUp_비밀번호_불일치_예외발생() {
        // given
        SignUpRequestDto mismatchPasswordDto =
                SignUpRequestDto.builder()
                        .name("testUser")
                        .email(TEST_EMAIL)
                        .verificationCode("123456")
                        .password(TEST_PASSWORD)
                        .passwordConfirm("999999")
                        .build();

        when(membersRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());
        when(emailVerificationService.verifyCode(TEST_EMAIL, "123456")).thenReturn(true);

        // when & then
        assertThatThrownBy(() -> formAuthService.signUp(mismatchPasswordDto))
                .isInstanceOf(AuthException.class)
                .hasMessage(ErrorCode.PASSWORD_MISMATCH.getMessage());

        verify(passwordEncoder, never()).encode(any());
        verify(membersRepository, never()).save(any());
    }

    // 2. 로그인
    @Test
    void login_정상_로그인_성공() {
        // given
        Members member =
                new Members(
                        1L,
                        TEST_EMAIL,
                        "testUser",
                        "LOCAL",
                        "profile.png",
                        30000000,
                        0,
                        LocalDateTime.now());
        member.setPassword(ENCODED_PASSWORD);

        TokenPair expectedTokenPair =
                TokenPair.builder()
                        .accessToken("access-token")
                        .refreshToken("refresh-token")
                        .build();

        when(membersRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(member));
        when(passwordEncoder.matches(TEST_PASSWORD, ENCODED_PASSWORD)).thenReturn(true);
        when(jwtTokenProvider.generateTokenPair(member)).thenReturn(expectedTokenPair);

        // when
        TokenPair result = formAuthService.login(validLoginDto);

        // then
        assertThat(result).isEqualTo(expectedTokenPair);
        verify(membersRepository).findByEmail(TEST_EMAIL);
        verify(passwordEncoder).matches(TEST_PASSWORD, ENCODED_PASSWORD);
        verify(jwtTokenProvider).generateTokenPair(member);
    }

    @Test
    void login_존재하지_않는_이메일_예외발생() {
        // given
        when(membersRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());

        // when & then
        assertThatThrownBy(() -> formAuthService.login(validLoginDto))
                .isInstanceOf(AuthException.class)
                .hasMessage(ErrorCode.INVALID_CREDENTIALS.getMessage());

        verify(passwordEncoder, never()).matches(any(), any());
        verify(jwtTokenProvider, never()).generateTokenPair(any());
    }

    @Test
    void login_소셜_로그인_계정_예외발생() {
        // given
        Members socialMember =
                new Members(
                        1L,
                        TEST_EMAIL,
                        "testUser",
                        "GOOGLE",
                        "profile.png",
                        30000000,
                        0,
                        LocalDateTime.now());

        when(membersRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(socialMember));

        // when & then
        assertThatThrownBy(() -> formAuthService.login(validLoginDto))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("GOOGLE 계정이 존재합니다");

        verify(passwordEncoder, never()).matches(any(), any());
        verify(jwtTokenProvider, never()).generateTokenPair(any());
    }

    @Test
    void login_잘못된_비밀번호_예외발생() {
        // given
        Members member =
                new Members(
                        1L,
                        TEST_EMAIL,
                        "testUser",
                        "LOCAL",
                        "profile.png",
                        30000000,
                        0,
                        LocalDateTime.now());
        member.setPassword(ENCODED_PASSWORD);

        when(membersRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(member));
        when(passwordEncoder.matches(TEST_PASSWORD, ENCODED_PASSWORD)).thenReturn(false);

        // when & then
        assertThatThrownBy(() -> formAuthService.login(validLoginDto))
                .isInstanceOf(AuthException.class)
                .hasMessage(ErrorCode.PASSWORD_MISMATCH.getMessage());

        verify(jwtTokenProvider, never()).generateTokenPair(any());
    }

    // 3. 이메일 중복 확인
    @Test
    void emailCheck_이메일_중복_true_반환() {
        // given
        Members existingMember =
                new Members(
                        1L,
                        TEST_EMAIL,
                        "existing",
                        "LOCAL",
                        "profile.png",
                        30000000,
                        0,
                        LocalDateTime.now());
        when(membersRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(existingMember));

        // when
        boolean result = formAuthService.emailCheck(TEST_EMAIL);

        // then
        assertThat(result).isTrue();
        verify(membersRepository).findByEmail(TEST_EMAIL);
    }

    @Test
    void emailCheck_이메일_중복_없음_false_반환() {
        // given
        when(membersRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());

        // when
        boolean result = formAuthService.emailCheck(TEST_EMAIL);

        // then
        assertThat(result).isFalse();
        verify(membersRepository).findByEmail(TEST_EMAIL);
    }

    // 4. 비밀번호 재설정
    @Test
    void resetPassword_정상_비밀번호_재설정_성공() {
        // given
        String newPassword = "newPassword123!";
        String encodedNewPassword = "encodedNewPassword123";

        Members localMember =
                new Members(
                        1L,
                        TEST_EMAIL,
                        "testUser",
                        "LOCAL",
                        "profile.png",
                        30000000,
                        0,
                        LocalDateTime.now());
        localMember.setPassword("oldEncodedPassword");

        when(membersRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(localMember));
        when(passwordEncoder.encode(newPassword)).thenReturn(encodedNewPassword);

        // when
        formAuthService.resetPassword(TEST_EMAIL, newPassword);

        // then
        assertThat(localMember.getPassword()).isEqualTo(encodedNewPassword);
        verify(membersRepository).findByEmail(TEST_EMAIL);
        verify(passwordEncoder).encode(newPassword);
    }

    @Test
    void resetPassword_소셜_로그인_계정_예외발생() {
        // given
        String newPassword = "newPassword123!";
        Members socialMember =
                new Members(
                        1L,
                        TEST_EMAIL,
                        "testUser",
                        "GOOGLE",
                        "profile.png",
                        30000000,
                        0,
                        LocalDateTime.now());

        when(membersRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(socialMember));

        // when & then
        assertThatThrownBy(() -> formAuthService.resetPassword(TEST_EMAIL, newPassword))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("소셜 로그인 계정은 비밀번호 재설정이 불가능합니다.");

        verify(passwordEncoder, never()).encode(any());
        assertThat(socialMember.getPassword()).isNull();
    }
}
