package io.gaboja9.mockstock.domain.mails.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;

import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@Builder
public class MailsResponseDto {

    @Schema(description = "제목")
    private String subject;

    @Schema(description = "내용")
    private String content;

    @Schema(description = "읽음 여부")
    private boolean unread;

    @Schema(description = "수신 시간")
    private LocalDateTime receivedAt;
}
