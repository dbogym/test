package io.gaboja9.mockstock.domain.members.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class MemoResponseDto {
    @Schema(description = "메모")
    private String memo;
}
