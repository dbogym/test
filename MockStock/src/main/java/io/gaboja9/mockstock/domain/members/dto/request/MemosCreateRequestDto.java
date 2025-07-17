package io.gaboja9.mockstock.domain.members.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class MemosCreateRequestDto {

    @Schema(description = "메모 작성")
    @NotBlank
    @Size(min = 1, max = 50)
    private String memo;
}
