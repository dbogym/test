package io.gaboja9.mockstock.domain.favorites.service;

import io.gaboja9.mockstock.domain.favorites.dto.response.FavoriteResponse;
import io.gaboja9.mockstock.domain.favorites.entity.Favorites;
import io.gaboja9.mockstock.domain.favorites.exception.FavoriteAlreadyExistException;
import io.gaboja9.mockstock.domain.favorites.exception.NotFoundFavoriteException;
import io.gaboja9.mockstock.domain.favorites.mapper.FavoritesMapper;
import io.gaboja9.mockstock.domain.favorites.repository.FavoritesRepository;
import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.members.exception.NotFoundMemberException;
import io.gaboja9.mockstock.domain.members.repository.MembersRepository;
import io.gaboja9.mockstock.domain.stock.entity.Stocks;
import io.gaboja9.mockstock.domain.stock.exception.NotFoundStockException;
import io.gaboja9.mockstock.domain.stock.repository.StocksRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class FavoritesService {

    private final FavoritesRepository favoritesRepository;
    private final StocksRepository stocksRepository;
    private final MembersRepository membersRepository;
    private final FavoritesMapper favoritesMapper;

    @Transactional
    public FavoriteResponse addFavorite(Long memberId, String stockCode) {
        Stocks stock =
                stocksRepository
                        .findByStockCode(stockCode)
                        .orElseThrow(() -> new NotFoundStockException(stockCode));

        Members member =
                membersRepository
                        .findById(memberId)
                        .orElseThrow(() -> new NotFoundMemberException(memberId));

        if (favoritesRepository.existsByMembersAndStocks(member, stock)) {
            throw new FavoriteAlreadyExistException(stock.getStockCode());
        }

        Favorites favorite = Favorites.builder().members(member).stocks(stock).build();

        Favorites savedFavorite = favoritesRepository.save(favorite);

        return favoritesMapper.toDto(favorite);
    }

    public void removeFavorite(Long memberId, String stockCode) {
        Stocks stock =
                stocksRepository
                        .findByStockCode(stockCode)
                        .orElseThrow(() -> new NotFoundStockException(stockCode));

        Members member =
                membersRepository
                        .findById(memberId)
                        .orElseThrow(() -> new NotFoundMemberException(memberId));

        Favorites favorite =
                favoritesRepository
                        .findByMembersAndStocks(member, stock)
                        .orElseThrow(() -> new NotFoundFavoriteException(memberId, stockCode));

        favoritesRepository.delete(favorite);
    }

    public List<FavoriteResponse> getMemberFavorites(Long memberId) {
        Members member =
                membersRepository
                        .findById(memberId)
                        .orElseThrow(() -> new NotFoundMemberException(memberId));

        List<Favorites> favorites = favoritesRepository.findByMembersOrderByCreatedAtDesc(member);

        return favoritesMapper.toDtoList(favorites);
    }
}
