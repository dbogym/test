package io.gaboja9.mockstock.domain.stock.repository;

import io.gaboja9.mockstock.domain.stock.entity.Stocks;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface StocksRepository extends JpaRepository<Stocks, Long> {
    Optional<Stocks> findByStockCode(String stockCode);
}
