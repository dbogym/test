package io.gaboja9.mockstock.domain.mails.service;

import io.gaboja9.mockstock.domain.mails.dto.response.MailsResponseDto;
import io.gaboja9.mockstock.domain.mails.entity.Mails;
import io.gaboja9.mockstock.domain.mails.mapper.MailsMapper;
import io.gaboja9.mockstock.domain.mails.repository.MailsRepository;
import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.members.exception.NotFoundMemberException;
import io.gaboja9.mockstock.domain.members.repository.MembersRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class MailsService {

    private final MailsRepository mailsRepository;

    private final MembersRepository membersRepository;

    private final MailsMapper mailsMapper;

    @Transactional(readOnly = true)
    public Page<MailsResponseDto> getAllMails(Long memberId, Pageable pageable) {

        Members findMember =
                membersRepository
                        .findById(memberId)
                        .orElseThrow(() -> new NotFoundMemberException(memberId));

        Page<Mails> mailsPage = mailsRepository.findByMembersId(findMember.getId(), pageable);

        return mailsPage.map(mailsMapper::toDto);
    }

    @Transactional(readOnly = true)
    public Page<MailsResponseDto> getMailsByUnreadStatus(
            Long memberId, boolean unread, Pageable pageable) {

        Members findMember =
                membersRepository
                        .findById(memberId)
                        .orElseThrow(() -> new NotFoundMemberException(memberId));

        Page<Mails> mailsPage =
                mailsRepository.findByMembersIdAndUnread(findMember.getId(), unread, pageable);

        return mailsPage.map(mailsMapper::toDto);
    }
}
