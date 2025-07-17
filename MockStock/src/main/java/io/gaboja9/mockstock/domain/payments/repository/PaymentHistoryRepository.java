package io.gaboja9.mockstock.domain.payments.repository;

import io.gaboja9.mockstock.domain.payments.entity.PaymentHistory;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface PaymentHistoryRepository extends JpaRepository<PaymentHistory, Long> {

    Optional<PaymentHistory> findByTidAndMembersId(String tid, Long membersId);

    @Query(
            """
            SELECT p.tid
            FROM PaymentHistory p
            WHERE p.members.id = :memberId
              AND p.status = 'READY'
            ORDER BY p.createdAt DESC
            LIMIT 1
            """)
    Optional<String> findLatestTidByMemberAndStatusReady(@Param("memberId") Long memberId);
}
