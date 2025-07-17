package io.gaboja9.mockstock.domain.mails.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import io.gaboja9.mockstock.domain.mails.dto.response.MailsResponseDto;
import io.gaboja9.mockstock.domain.mails.entity.Mails;
import io.gaboja9.mockstock.domain.mails.mapper.MailsMapper;
import io.gaboja9.mockstock.domain.mails.repository.MailsRepository;
import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.members.exception.NotFoundMemberException;
import io.gaboja9.mockstock.domain.members.repository.MembersRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.data.domain.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public class MailsServiceTest {

    @Mock private MailsRepository mailsRepository;

    @Mock private MembersRepository membersRepository;

    @Mock private MailsMapper mailsMapper;

    @InjectMocks private MailsService mailsService;

    private Members testMember;
    private Mails testMail;
    private Mails testMail2;
    private MailsResponseDto testDto;
    private MailsResponseDto testDto2;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        testMember =
                new Members(
                        1L,
                        "test@example.com",
                        "testUser",
                        "google",
                        "test.png",
                        5000,
                        0,
                        LocalDateTime.now());

        testMail =
                new Mails("Test Subject", "Test Content", false, LocalDateTime.now(), testMember);
        testMail2 =
                new Mails("Test Subject2", "Test Content2", true, LocalDateTime.now(), testMember);

        testDto =
                MailsResponseDto.builder()
                        .subject("Test Subject")
                        .content("Test Content")
                        .unread(false)
                        .receivedAt(LocalDateTime.now())
                        .build();

        testDto2 =
                MailsResponseDto.builder()
                        .subject("Test Subject2")
                        .content("Test Content2")
                        .unread(true)
                        .receivedAt(LocalDateTime.now())
                        .build();
    }

    @Test
    void getAllMails_정상동작() {
        // given
        Long memberId = 1L;
        Pageable pageable = PageRequest.of(0, 1, Sort.by("createdAt").descending());
        Page<Mails> mailsPage = new PageImpl<>(List.of(testMail));

        when(membersRepository.findById(memberId)).thenReturn(Optional.of(testMember));
        when(mailsRepository.findByMembersId(testMember.getId(), pageable)).thenReturn(mailsPage);
        when(mailsMapper.toDto(testMail)).thenReturn(testDto);

        // when
        Page<MailsResponseDto> result = mailsService.getAllMails(memberId, pageable);

        // then
        assertEquals(1, result.getTotalElements());
        assertEquals("Test Subject", result.getContent().get(0).getSubject());

        verify(membersRepository).findById(memberId);
        verify(mailsRepository).findByMembersId(testMember.getId(), pageable);
        verify(mailsMapper).toDto(testMail);
    }

    @Test
    void getAllMails_유저없음예외() {
        Long memberId = 2L;
        Pageable pageable = PageRequest.of(0, 10);

        when(membersRepository.findById(memberId)).thenReturn(Optional.empty());

        assertThrows(
                NotFoundMemberException.class, () -> mailsService.getAllMails(memberId, pageable));

        verify(membersRepository).findById(memberId);
        verifyNoMoreInteractions(mailsRepository);
        verifyNoMoreInteractions(mailsMapper);
    }

    @Test
    void getMailsByReadStatus_정상동작() {
        // given
        Long memberId = 1L;
        boolean unread = true;
        Pageable pageable = PageRequest.of(0, 10);
        Page<Mails> mailsPage = new PageImpl<>(List.of(testMail2));

        when(membersRepository.findById(memberId)).thenReturn(Optional.of(testMember));
        when(mailsRepository.findByMembersIdAndUnread(testMember.getId(), unread, pageable))
                .thenReturn(mailsPage);
        when(mailsMapper.toDto(testMail2)).thenReturn(testDto2);

        // when
        Page<MailsResponseDto> result =
                mailsService.getMailsByUnreadStatus(memberId, unread, pageable);

        // then
        assertEquals(1, result.getContent().size());
        assertTrue(result.getContent().get(0).isUnread());

        verify(membersRepository).findById(memberId);
        verify(mailsRepository).findByMembersIdAndUnread(testMember.getId(), unread, pageable);
        verify(mailsMapper).toDto(testMail2);
    }

    @Test
    void getMailsByReadStatus_유저없음예외() {
        Long memberId = 3L;
        Pageable pageable = PageRequest.of(0, 10);

        when(membersRepository.findById(memberId)).thenReturn(Optional.empty());

        assertThrows(
                NotFoundMemberException.class,
                () -> mailsService.getMailsByUnreadStatus(memberId, true, pageable));

        verify(membersRepository).findById(memberId);
        verifyNoMoreInteractions(mailsRepository);
        verifyNoMoreInteractions(mailsMapper);
    }
}
