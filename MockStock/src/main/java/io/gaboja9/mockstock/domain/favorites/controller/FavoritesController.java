package io.gaboja9.mockstock.domain.favorites.controller;

import io.gaboja9.mockstock.domain.auth.dto.MembersDetails;
import io.gaboja9.mockstock.domain.favorites.dto.response.FavoriteResponse;
import io.gaboja9.mockstock.domain.favorites.service.FavoritesService;

import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/favorites")
@RequiredArgsConstructor
public class FavoritesController {

    private final FavoritesService favoritesService;

    @PostMapping("/{stockCode}")
    public ResponseEntity<FavoriteResponse> addFavorite(
            @AuthenticationPrincipal MembersDetails membersDetails,
            @PathVariable String stockCode) {
        FavoriteResponse response = favoritesService.addFavorite(membersDetails.getId(), stockCode);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{stockCode}")
    public ResponseEntity<Void> removeFavorite(
            @AuthenticationPrincipal MembersDetails membersDetails,
            @PathVariable String stockCode) {
        favoritesService.removeFavorite(membersDetails.getId(), stockCode);
        return ResponseEntity.ok(null);
    }

    @GetMapping()
    public ResponseEntity<List<FavoriteResponse>> getMemberFavorites(
            @AuthenticationPrincipal MembersDetails membersDetails) {
        List<FavoriteResponse> responses =
                favoritesService.getMemberFavorites(membersDetails.getId());
        return ResponseEntity.ok(responses);
    }
}
