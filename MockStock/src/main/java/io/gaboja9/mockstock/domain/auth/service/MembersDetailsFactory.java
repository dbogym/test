package io.gaboja9.mockstock.domain.auth.service;

import io.gaboja9.mockstock.domain.auth.dto.MembersDetails;
import io.gaboja9.mockstock.domain.auth.exception.UnavailableProviderException;

import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;

public class MembersDetailsFactory {
    public static MembersDetails membersDetails(String provider, OAuth2User oAuth2User) {

        Map<String, Object> attributes = oAuth2User.getAttributes();

        switch (provider.toUpperCase().trim()) {
            case "GOOGLE" -> {
                return MembersDetails.builder()
                        .name(attributes.get("name").toString())
                        .email(attributes.get("email").toString())
                        .profileImage(attributes.get("picture").toString())
                        .attributes(attributes)
                        .build();
            }
            case "NAVER" -> {
                Map<String, String> properties = (Map<String, String>) attributes.get("response");
                return MembersDetails.builder()
                        .name(properties.get("name"))
                        .email(properties.get("id") + "@naver.com")
                        .profileImage(properties.get("profile_image"))
                        .attributes(attributes)
                        .build();
            }

            case "KAKAO" -> {
                Map<String, String> properties = (Map<String, String>) attributes.get("properties");
                return MembersDetails.builder()
                        .name(properties.get("nickname"))
                        .email(attributes.get("id") + "@kakao.com")
                        .profileImage(properties.get("profile_image"))
                        .attributes(attributes)
                        .build();
            }
            default -> throw new UnavailableProviderException("지원하지 않는 제공자: " + provider);
        }
    }
}
