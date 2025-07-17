package io.gaboja9.mockstock.domain.mails.mapper;

import io.gaboja9.mockstock.domain.mails.dto.response.MailsResponseDto;
import io.gaboja9.mockstock.domain.mails.entity.Mails;

import org.springframework.stereotype.Component;

@Component
public class MailsMapper {

    public MailsResponseDto toDto(Mails mail) {
        if (mail == null) {
            return null;
        }

        return MailsResponseDto.builder()
                .subject(mail.getSubject())
                .content(mail.getContent())
                .unread(mail.isUnread())
                .receivedAt(mail.getCreatedAt())
                .build();
    }
}
