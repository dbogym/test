package io.gaboja9.mockstock.domain.trades.repository;

import io.gaboja9.mockstock.domain.trades.entity.Trades;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

@Repository
public interface TradesRepository extends CrudRepository<Trades, Long> {

    int countByMembersId(Long memberId);

    @EntityGraph(attributePaths = {"members"})
    @Query("SELECT t FROM Trades t WHERE t.members.id = :membersId")
    Page<Trades> findByMembersId(@Param("membersId") Long membersId, Pageable pageable);

    @EntityGraph(attributePaths = {"members"})
    @Query(
            "SELECT DISTINCT t FROM Trades t WHERE "
                    + "(t.stockCode = :stockCode OR t.stockName = :stockName) "
                    + "AND t.createdAt BETWEEN :startDateTime AND :endDateTime "
                    + "AND t.members.id = :membersId")
    Page<Trades> findByStockCodeOrStockNameAndCreatedAtBetween(
            @Param("stockCode") String stockCode,
            @Param("stockName") String stockName,
            @Param("startDateTime") LocalDateTime startDateTime,
            @Param("endDateTime") LocalDateTime endDateTime,
            @Param("membersId") Long membersId,
            Pageable pageable);
}
