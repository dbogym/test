package io.gaboja9.mockstock.domain.mails.repository;

import io.gaboja9.mockstock.domain.mails.entity.Mails;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MailsRepository extends JpaRepository<Mails, Long> {

    Page<Mails> findByMembersId(Long memberId, Pageable pageable);

    Page<Mails> findByMembersIdAndUnread(Long memberId, boolean unread, Pageable pageable);
}
