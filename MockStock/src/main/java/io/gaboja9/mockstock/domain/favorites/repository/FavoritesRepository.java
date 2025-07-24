package io.gaboja9.mockstock.domain.favorites.repository;

import io.gaboja9.mockstock.domain.favorites.entity.Favorites;
import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.stock.entity.Stocks;

import org.springframework.data.repository.CrudRepository;

import java.util.List;
import java.util.Optional;

public interface FavoritesRepository extends CrudRepository<Favorites, Long> {
    boolean existsByMembersAndStocks(Members member, Stocks stock);

    Optional<Favorites> findByMembersAndStocks(Members member, Stocks stock);

    List<Favorites> findByMembersOrderByCreatedAtDesc(Members member);
}
