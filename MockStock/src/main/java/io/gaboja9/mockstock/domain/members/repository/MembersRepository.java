package io.gaboja9.mockstock.domain.members.repository;

import io.gaboja9.mockstock.domain.members.entity.Members;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MembersRepository extends JpaRepository<Members, Long> {
    Optional<Members> findByEmail(String email);
}
