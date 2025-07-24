package io.gaboja9.mockstock.domain.portfolios.repository;

import io.gaboja9.mockstock.domain.portfolios.entity.Portfolios;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PortfoliosRepository extends JpaRepository<Portfolios, Long> {

    List<Portfolios> findByMembersId(Long memberId);

    void deleteByMembersId(Long memberId);

    Optional<Portfolios> findByMembersIdAndStockCode(Long memberId, String stockCode);
}
