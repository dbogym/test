package io.gaboja9.mockstock.domain.auth.repository;

import io.gaboja9.mockstock.domain.auth.entity.RefreshTokenBlackList;

import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenBlackListRepository
        extends JpaRepository<RefreshTokenBlackList, Long> {}
