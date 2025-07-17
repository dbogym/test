package io.gaboja9.mockstock.domain.auth.service;

import io.gaboja9.mockstock.domain.auth.dto.MembersDetails;
import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.members.enums.Role;
import io.gaboja9.mockstock.domain.members.repository.MembersRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.NoSuchElementException;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class AuthService extends DefaultOAuth2UserService {

    private final MembersRepository membersRepository;

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
}
