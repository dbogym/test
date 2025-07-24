package io.gaboja9.mockstock.domain.orders.repository;

import io.gaboja9.mockstock.domain.orders.entity.Orders;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OrdersRepository extends JpaRepository<Orders, Long> {}
