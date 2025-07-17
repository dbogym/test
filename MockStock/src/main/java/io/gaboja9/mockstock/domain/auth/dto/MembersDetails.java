package io.gaboja9.mockstock.domain.auth.dto;

import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.members.enums.Role;

import lombok.*;
import lombok.experimental.Accessors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.List;
import java.util.Map;

@Getter
@Accessors(chain = true)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class MembersDetails implements OAuth2User {

    @Setter private Long id;

    private String name;
    private String email;
    private String profileImage;
    @Setter private Map<String, Object> attributes;

    @Setter private Role role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    public static MembersDetails from(Members members) {
        MembersDetails membersDetails = new MembersDetails();

        membersDetails.id = members.getId();

        membersDetails.email = members.getEmail();

        membersDetails.role = members.getRole();
        membersDetails.profileImage = members.getProfileImage();

        return membersDetails;
    }

    @Builder
    public MembersDetails(
            String name, String email, String profileImage, Map<String, Object> attributes) {
        this.name = name;
        this.email = email;
        this.profileImage = profileImage;
        this.attributes = attributes;
    }
}
