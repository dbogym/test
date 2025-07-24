package io.gaboja9.mockstock.domain.notifications.repository;

import io.gaboja9.mockstock.domain.notifications.entity.Notifications;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface NotificationsRepository extends JpaRepository<Notifications, Long> {
    Optional<Notifications> findByMembersId(Long memberId);
}
