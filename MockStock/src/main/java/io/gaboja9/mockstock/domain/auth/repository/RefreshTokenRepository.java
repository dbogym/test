package io.gaboja9.mockstock.domain.auth.repository;

import io.gaboja9.mockstock.domain.auth.entity.RefreshToken;

import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {}
