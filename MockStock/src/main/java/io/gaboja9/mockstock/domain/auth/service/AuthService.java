package io.gaboja9.mockstock.domain.auth.service;

import io.gaboja9.mockstock.domain.auth.dto.MembersDetails;
import io.gaboja9.mockstock.domain.auth.dto.TokenPair;
import io.gaboja9.mockstock.domain.auth.dto.request.LoginRequestDto;
import io.gaboja9.mockstock.domain.auth.dto.request.SignUpRequestDto;
import io.gaboja9.mockstock.domain.auth.exception.AuthException;
import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.members.enums.Role;
import io.gaboja9.mockstock.domain.members.repository.MembersRepository;

import org.springframework.transaction.annotation.Transactional;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class AuthService extends DefaultOAuth2UserService {

    private final MembersRepository membersRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailVerificationService emailVerificationService;
    private final JwtTokenProvider jwtTokenProvider;

    // OAuth
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);
        log.info("oAuth2User = {}", oAuth2User);

        String provider = userRequest.getClientRegistration().getRegistrationId().toUpperCase();
        log.info("userRequest = {}", provider);

        MembersDetails membersDetails = MembersDetailsFactory.membersDetails(provider, oAuth2User);

        Optional<Members> membersOptional =
                membersRepository.findByEmail(membersDetails.getEmail());

        Members findMember =
                membersOptional.orElseGet(
                        () -> {
                            Members saved =
                                    Members.builder()
                                            .nickname(membersDetails.getName())
                                            .email(membersDetails.getEmail())
                                            .provider(provider)
                                            .role(Role.MEMBER)
                                            .profileImage(membersDetails.getProfileImage())
                                            .cashBalance(30000000)
                                            .bankruptcyCnt(0)
                                            .password(null)
                                            .build();
                            return membersRepository.save(saved);
                        });

        if (findMember.getProvider().equals(provider)) {
            return membersDetails.setId(findMember.getId()).setRole(findMember.getRole());
        } else {
            throw new IllegalStateException("이미 다른 이메일로 가입되어 있는 유저입니다. 다시 로그인해주세요.");
        }
    }

    public Optional<Members> findById(Long id) {
        return membersRepository.findById(id);
    }

    public Members getById(Long id) {
        return findById(id).orElseThrow(() -> new NoSuchElementException());
    }

    public MembersDetails getMembersDetailsById(Long id) {
        Members findMembers = getById(id);
        return MembersDetails.from(findMembers);
    }

    // form 회원가입
    public void signUp(SignUpRequestDto dto) {

        // 이메일 중복 확인
        if (membersRepository.findByEmail(dto.getEmail()).isPresent()) {
            throw AuthException.emailAlreadyExists();
        }

        // 인증코드 확인
        if (!emailVerificationService.verifyCode(dto.getEmail(), dto.getVerificationCode())) {
            throw AuthException.invalidVerificationCode();
        }

        // 비밀번호 확인
        if (!dto.getPassword().equals(dto.getPasswordConfirm())) {
            throw AuthException.passwordMismatch();
        }

        String encodedPassword = passwordEncoder.encode(dto.getPassword());

        Members member =
                Members.builder()
                        .nickname(dto.getName())
                        .email(dto.getEmail())
                        .password(encodedPassword)
                        .role(Role.MEMBER)
                        .profileImage(null)
                        .provider("LOCAL")
                        .cashBalance(30000000)
                        .bankruptcyCnt(0)
                        .build();

        membersRepository.save(member);
        log.info("회원가입 완료: {}", dto.getEmail());
    }

    // form 로그인
    @Transactional(readOnly = true)
    public TokenPair login(LoginRequestDto dto) {
        log.info("로그인 시도: {}", dto.getEmail());

        // 이메일로 회원 조회
        Optional<Members> member = membersRepository.findByEmail(dto.getEmail());
        if (member.isEmpty()) {
            throw AuthException.invalidCredentials();
        }

        // LOCAL 사용자인지 확인
        if (!member.get().getProvider().equals("LOCAL")) {
            throw AuthException.socialLoginRequired(member.get().getProvider());
        }

        // 비밀번호 확인
        if (!passwordEncoder.matches(dto.getPassword(), member.get().getPassword())) {
            throw AuthException.passwordMismatch();
        }

        TokenPair tokenPair = jwtTokenProvider.generateTokenPair(member.get());
        log.info("로그인 성공: {}", dto.getEmail());

        return tokenPair;
    }

    // 이메일 중복 확인
    public boolean emailCheck(String email) {
        return membersRepository.findByEmail(email).isPresent();
    }

    // 비밀번호 재설정
    public void resetPassword(String email, String newPassword) {
        Optional<Members> member = membersRepository.findByEmail(email);

        if (!"LOCAL".equals(member.get().getProvider())) {
            throw new IllegalStateException("소셜 로그인 계정은 비밀번호 재설정아 불가능합니다.");
        }

        String encodedPassword = passwordEncoder.encode(newPassword);
        member.get().setPassword(encodedPassword);

        log.info("비밀번호 재설정 완료: {}", email);
    }
}
