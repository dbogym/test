package io.gaboja9.mockstock.domain.auth.dto;

import io.gaboja9.mockstock.domain.members.enums.Role;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TokenBody {

    private Long memberId;
    private Role role;
}
