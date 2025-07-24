package io.gaboja9.mockstock.domain.favorites.mapper;

import io.gaboja9.mockstock.domain.favorites.dto.response.FavoriteResponse;
import io.gaboja9.mockstock.domain.favorites.entity.Favorites;

import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class FavoritesMapper {

    public FavoriteResponse toDto(Favorites favorites) {
        return FavoriteResponse.builder()
                .memberId(favorites.getMembers().getId())
                .stockCode(favorites.getStocks().getStockCode())
                .stockName(favorites.getStocks().getStockName())
                .build();
    }

    public List<FavoriteResponse> toDtoList(List<Favorites> favorites) {
        return favorites.stream().map(this::toDto).toList();
    }
}
