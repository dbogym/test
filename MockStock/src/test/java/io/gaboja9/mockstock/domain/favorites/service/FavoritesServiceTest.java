package io.gaboja9.mockstock.domain.favorites.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.*;

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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@ExtendWith(MockitoExtension.class)
@DisplayName("FavoritesService 테스트")
class FavoritesServiceTest {

    @Mock private FavoritesRepository favoritesRepository;

    @Mock private StocksRepository stocksRepository;

    @Mock private MembersRepository membersRepository;

    @Mock private FavoritesMapper favoritesMapper;

    @InjectMocks private FavoritesService favoritesService;

    private Members testMember;
    private Stocks testStock;
    private Favorites testFavorite;
    private FavoriteResponse testFavoriteResponse;

    @BeforeEach
    void setUp() {
        // 테스트용 Members 객체 생성
        testMember =
                Members.builder().id(1L).email("test@example.com").nickname("testUser").build();

        // 테스트용 Stocks 객체 생성
        testStock = Stocks.builder().id(1L).stockName("삼성전자").stockCode("005930").build();

        // 테스트용 Favorites 객체 생성
        testFavorite = Favorites.builder().id(1L).members(testMember).stocks(testStock).build();

        // 테스트용 FavoriteResponse 객체 생성
        testFavoriteResponse =
                FavoriteResponse.builder()
                        .memberId(1L)
                        .stockName("삼성전자")
                        .stockCode("005930")
                        .build();
    }

    @Nested
    @DisplayName("addFavorite 메서드 테스트")
    class AddFavoriteTest {

        @Test
        @DisplayName("정상적인 관심종목 등록이 성공한다")
        void addFavorite_success() {
            // given
            Long memberId = 1L;
            String stockCode = "005930";

            given(stocksRepository.findByStockCode(stockCode)).willReturn(Optional.of(testStock));
            given(membersRepository.findById(memberId)).willReturn(Optional.of(testMember));
            given(favoritesRepository.existsByMembersAndStocks(testMember, testStock))
                    .willReturn(false);
            given(favoritesRepository.save(any(Favorites.class))).willReturn(testFavorite);
            given(favoritesMapper.toDto(any(Favorites.class))).willReturn(testFavoriteResponse);

            // when
            FavoriteResponse result = favoritesService.addFavorite(memberId, stockCode);

            // then
            assertThat(result).isNotNull();
            assertThat(result.getMemberId()).isEqualTo(1L);
            assertThat(result.getStockCode()).isEqualTo("005930");
            assertThat(result.getStockName()).isEqualTo("삼성전자");

            then(stocksRepository).should().findByStockCode(stockCode);
            then(membersRepository).should().findById(memberId);
            then(favoritesRepository).should().existsByMembersAndStocks(testMember, testStock);
            then(favoritesRepository).should().save(any(Favorites.class));
            then(favoritesMapper).should().toDto(any(Favorites.class));
        }

        @Test
        @DisplayName("존재하지 않는 주식 코드로 등록 시 예외가 발생한다")
        void addFavorite_StockNotFound_ThrowsException() {
            // given
            Long memberId = 1L;
            String invalidStockCode = "999999";

            given(stocksRepository.findByStockCode(invalidStockCode)).willReturn(Optional.empty());

            // when & then
            assertThatThrownBy(() -> favoritesService.addFavorite(memberId, invalidStockCode))
                    .isInstanceOf(NotFoundStockException.class);

            then(stocksRepository).should().findByStockCode(invalidStockCode);
            then(membersRepository).should(never()).findById(anyLong());
            then(favoritesRepository).should(never()).save(any(Favorites.class));
        }

        @Test
        @DisplayName("존재하지 않는 회원으로 등록 시 예외가 발생한다")
        void addFavorite_MemberNotFound_ThrowsException() {
            // given
            Long invalidMemberId = 999L;
            String stockCode = "005930";

            given(stocksRepository.findByStockCode(stockCode)).willReturn(Optional.of(testStock));
            given(membersRepository.findById(invalidMemberId)).willReturn(Optional.empty());

            // when & then
            assertThatThrownBy(() -> favoritesService.addFavorite(invalidMemberId, stockCode))
                    .isInstanceOf(NotFoundMemberException.class);

            then(stocksRepository).should().findByStockCode(stockCode);
            then(membersRepository).should().findById(invalidMemberId);
            then(favoritesRepository).should(never()).save(any(Favorites.class));
        }

        @Test
        @DisplayName("이미 등록된 관심종목을 다시 등록 시 예외가 발생한다")
        void addFavorite_AlreadyExists_ThrowsException() {
            // given
            Long memberId = 1L;
            String stockCode = "005930";

            given(stocksRepository.findByStockCode(stockCode)).willReturn(Optional.of(testStock));
            given(membersRepository.findById(memberId)).willReturn(Optional.of(testMember));
            given(favoritesRepository.existsByMembersAndStocks(testMember, testStock))
                    .willReturn(true);

            // when & then
            assertThatThrownBy(() -> favoritesService.addFavorite(memberId, stockCode))
                    .isInstanceOf(FavoriteAlreadyExistException.class);

            then(stocksRepository).should().findByStockCode(stockCode);
            then(membersRepository).should().findById(memberId);
            then(favoritesRepository).should().existsByMembersAndStocks(testMember, testStock);
            then(favoritesRepository).should(never()).save(any(Favorites.class));
        }
    }

    @Nested
    @DisplayName("removeFavorite 메서드 테스트")
    class RemoveFavoriteTest {

        @Test
        @DisplayName("정상적인 관심종목 해제가 성공한다")
        void removeFavorite_Success() {
            // given
            Long memberId = 1L;
            String stockCode = "005930";

            given(stocksRepository.findByStockCode(stockCode)).willReturn(Optional.of(testStock));
            given(membersRepository.findById(memberId)).willReturn(Optional.of(testMember));
            given(favoritesRepository.findByMembersAndStocks(testMember, testStock))
                    .willReturn(Optional.of(testFavorite));

            // when
            favoritesService.removeFavorite(memberId, stockCode);

            // then
            then(stocksRepository).should().findByStockCode(stockCode);
            then(membersRepository).should().findById(memberId);
            then(favoritesRepository).should().findByMembersAndStocks(testMember, testStock);
            then(favoritesRepository).should().delete(testFavorite);
        }

        @Test
        @DisplayName("존재하지 않는 주식 코드로 해제 시 예외가 발생한다")
        void removeFavorite_StockNotFound_ThrowsException() {
            // given
            Long memberId = 1L;
            String invalidStockCode = "999999";

            given(stocksRepository.findByStockCode(invalidStockCode)).willReturn(Optional.empty());

            // when & then
            assertThatThrownBy(() -> favoritesService.removeFavorite(memberId, invalidStockCode))
                    .isInstanceOf(NotFoundStockException.class);

            then(stocksRepository).should().findByStockCode(invalidStockCode);
            then(membersRepository).should(never()).findById(anyLong());
            then(favoritesRepository).should(never()).delete(any(Favorites.class));
        }

        @Test
        @DisplayName("존재하지 않는 회원으로 해제 시 예외가 발생한다")
        void removeFavorite_MemberNotFound_ThrowsException() {
            // given
            Long invalidMemberId = 999L;
            String stockCode = "005930";

            given(stocksRepository.findByStockCode(stockCode)).willReturn(Optional.of(testStock));
            given(membersRepository.findById(invalidMemberId)).willReturn(Optional.empty());

            // when & then
            assertThatThrownBy(() -> favoritesService.removeFavorite(invalidMemberId, stockCode))
                    .isInstanceOf(NotFoundMemberException.class);

            then(stocksRepository).should().findByStockCode(stockCode);
            then(membersRepository).should().findById(invalidMemberId);
            then(favoritesRepository).should(never()).delete(any(Favorites.class));
        }

        @Test
        @DisplayName("등록되지 않은 관심종목을 해제 시 예외가 발생한다")
        void removeFavorite_FavoriteNotFound_ThrowsException() {
            // given
            Long memberId = 1L;
            String stockCode = "005930";

            given(stocksRepository.findByStockCode(stockCode)).willReturn(Optional.of(testStock));
            given(membersRepository.findById(memberId)).willReturn(Optional.of(testMember));
            given(favoritesRepository.findByMembersAndStocks(testMember, testStock))
                    .willReturn(Optional.empty());

            // when & then
            assertThatThrownBy(() -> favoritesService.removeFavorite(memberId, stockCode))
                    .isInstanceOf(NotFoundFavoriteException.class);

            then(stocksRepository).should().findByStockCode(stockCode);
            then(membersRepository).should().findById(memberId);
            then(favoritesRepository).should().findByMembersAndStocks(testMember, testStock);
            then(favoritesRepository).should(never()).delete(any(Favorites.class));
        }
    }

    @Nested
    @DisplayName("getMemberFavorites 메서드 테스트")
    class GetMemberFavoritesTest {

        @Test
        @DisplayName("회원의 관심종목 목록을 정상적으로 조회한다")
        void getMemberFavorites_Success() {
            // given
            Long memberId = 1L;

            Stocks stock2 = Stocks.builder().id(2L).stockName("SK하이닉스").stockCode("000660").build();

            Favorites favorite2 =
                    Favorites.builder().id(2L).members(testMember).stocks(stock2).build();

            List<Favorites> favoritesList = Arrays.asList(testFavorite, favorite2);

            FavoriteResponse response2 =
                    FavoriteResponse.builder()
                            .memberId(1L)
                            .stockName("SK하이닉스")
                            .stockCode("000660")
                            .build();

            List<FavoriteResponse> expectedResponses =
                    Arrays.asList(testFavoriteResponse, response2);

            given(membersRepository.findById(memberId)).willReturn(Optional.of(testMember));
            given(favoritesRepository.findByMembersOrderByCreatedAtDesc(testMember))
                    .willReturn(favoritesList);
            given(favoritesMapper.toDtoList(favoritesList)).willReturn(expectedResponses);

            // when
            List<FavoriteResponse> result = favoritesService.getMemberFavorites(memberId);

            // then
            assertThat(result).hasSize(2);
            assertThat(result.get(0).getStockName()).isEqualTo("삼성전자");
            assertThat(result.get(1).getStockName()).isEqualTo("SK하이닉스");

            then(membersRepository).should().findById(memberId);
            then(favoritesRepository).should().findByMembersOrderByCreatedAtDesc(testMember);
            then(favoritesMapper).should().toDtoList(favoritesList);
        }

        @Test
        @DisplayName("존재하지 않는 회원의 관심종목 조회 시 예외가 발생한다")
        void getMemberFavorites_MemberNotFound_ThrowsException() {
            // given
            Long invalidMemberId = 999L;

            given(membersRepository.findById(invalidMemberId)).willReturn(Optional.empty());

            // when & then
            assertThatThrownBy(() -> favoritesService.getMemberFavorites(invalidMemberId))
                    .isInstanceOf(NotFoundMemberException.class);

            then(membersRepository).should().findById(invalidMemberId);
            then(favoritesRepository)
                    .should(never())
                    .findByMembersOrderByCreatedAtDesc(any(Members.class));
        }

        @Test
        @DisplayName("관심종목이 없는 회원의 경우 빈 리스트를 반환한다")
        void getMemberFavorites_EmptyList_Success() {
            // given
            Long memberId = 1L;
            List<Favorites> emptyList = List.of();
            List<FavoriteResponse> emptyResponseList = List.of();

            given(membersRepository.findById(memberId)).willReturn(Optional.of(testMember));
            given(favoritesRepository.findByMembersOrderByCreatedAtDesc(testMember))
                    .willReturn(emptyList);
            given(favoritesMapper.toDtoList(emptyList)).willReturn(emptyResponseList);

            // when
            List<FavoriteResponse> result = favoritesService.getMemberFavorites(memberId);

            // then
            assertThat(result).isEmpty();

            then(membersRepository).should().findById(memberId);
            then(favoritesRepository).should().findByMembersOrderByCreatedAtDesc(testMember);
            then(favoritesMapper).should().toDtoList(emptyList);
        }
    }
}
