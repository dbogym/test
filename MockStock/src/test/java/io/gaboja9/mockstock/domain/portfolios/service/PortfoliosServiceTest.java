package io.gaboja9.mockstock.domain.portfolios.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.members.exception.NotFoundMemberException;
import io.gaboja9.mockstock.domain.members.repository.MembersRepository;
import io.gaboja9.mockstock.domain.portfolios.dto.response.PortfolioResponseDto;
import io.gaboja9.mockstock.domain.portfolios.dto.response.PortfoliosResponseDto;
import io.gaboja9.mockstock.domain.portfolios.entity.Portfolios;
import io.gaboja9.mockstock.domain.portfolios.exception.NotFoundPortfolioException;
import io.gaboja9.mockstock.domain.portfolios.mapper.PortfoliosMapper;
import io.gaboja9.mockstock.domain.portfolios.repository.PortfoliosRepository;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@ExtendWith(MockitoExtension.class)
class PortfoliosServiceTest {

    @InjectMocks private PortfoliosService portfoliosService;

    @Mock private PortfoliosRepository portfoliosRepository;

    @Mock private PortfoliosMapper portfoliosMapper;

    @Mock private MembersRepository membersRepository;

    @Test
    void getPortfolios_정상작동() {
        Long memberId = 1L;

        Members member =
                new Members(
                        memberId,
                        "test@example.com",
                        "testUser",
                        "google",
                        "test.png",
                        5000,
                        0,
                        LocalDateTime.now().minusDays(15));

        Portfolios p1 = new Portfolios("AAPL", "애플", 10, 150, member);
        Portfolios p2 = new Portfolios("TSLA", "테슬라", 5, 200, member);

        List<Portfolios> portfoliosList = Arrays.asList(p1, p2);

        PortfolioResponseDto dto1 =
                PortfolioResponseDto.builder()
                        .stockCode("AAPL")
                        .stockName("애플")
                        .quantity(10)
                        .avgPrice(150)
                        .currentPrice(160)
                        .evaluationAmount(1600)
                        .profit(100)
                        .profitRate(6.666666666666667)
                        .build();

        PortfolioResponseDto dto2 =
                PortfolioResponseDto.builder()
                        .stockCode("TSLA")
                        .stockName("테슬라")
                        .quantity(5)
                        .avgPrice(200)
                        .currentPrice(220)
                        .evaluationAmount(1100)
                        .profit(100)
                        .profitRate(10.0)
                        .build();

        given(portfoliosRepository.findByMembersId(memberId)).willReturn(portfoliosList);
        given(portfoliosMapper.toDto(p1)).willReturn(dto1);
        given(portfoliosMapper.toDto(p2)).willReturn(dto2);
        given(membersRepository.findById(memberId)).willReturn(Optional.of(member));

        int totalEvaluationAmount = dto1.getEvaluationAmount() + dto2.getEvaluationAmount(); // 2700
        int totalProfit = dto1.getProfit() + dto2.getProfit(); // 200
        int totalInvestment =
                dto1.getAvgPrice() * dto1.getQuantity()
                        + dto2.getAvgPrice() * dto2.getQuantity(); // 2750
        double totalProfitRate = (double) totalProfit / totalInvestment * 100;

        PortfoliosResponseDto result = portfoliosService.getPortfolios(memberId);

        assertThat(result.getCashBalance()).isEqualTo(member.getCashBalance());
        assertThat(result.getTotalEvaluationAmount()).isEqualTo(totalEvaluationAmount);
        assertThat(result.getTotalProfit()).isEqualTo(totalProfit);
        assertThat(result.getTotalProfitRate()).isEqualTo(totalProfitRate);
        assertThat(result.getPortfolios()).containsExactly(dto1, dto2);
    }

    @Test
    void getPortfolios_유저없음_예외발생() {
        Long memberId = 999L;

        given(membersRepository.findById(memberId)).willReturn(Optional.empty());
        given(portfoliosRepository.findByMembersId(memberId)).willReturn(List.of());

        assertThrows(
                NotFoundMemberException.class, () -> portfoliosService.getPortfolios(memberId));
    }

    @Test
    void remove_정상동작() {
        // given
        Long memberId = 1L;
        Members member =
                new Members(
                        memberId,
                        "test@example.com",
                        "testUser",
                        "google",
                        "profile.png",
                        30_000_000,
                        0,
                        LocalDateTime.now().minusDays(10));

        given(membersRepository.findById(memberId)).willReturn(Optional.of(member));

        // when
        portfoliosService.remove(memberId);

        // then
        verify(membersRepository).findById(memberId);
        verify(portfoliosRepository).deleteByMembersId(memberId);
    }

    @Test
    void remove_유저없음_예외발생() {
        // given
        Long memberId = 999L;
        given(membersRepository.findById(memberId)).willReturn(Optional.empty());

        // when & then
        assertThrows(NotFoundMemberException.class, () -> portfoliosService.remove(memberId));

        verify(portfoliosRepository, never()).deleteByMembersId(any());
    }

    @Test
    void updateForBuy_기존보유종목_평균단가갱신() {
        // given
        Long memberId = 1L;
        String stockCode = "AAPL";
        String stockName = "애플";
        int quantity = 5;
        int price = 200;

        Members member =
                new Members(
                        memberId,
                        "test@example.com",
                        "testUser",
                        "google",
                        "profile.png",
                        30000000,
                        0,
                        LocalDateTime.now());

        Portfolios portfolio = new Portfolios(stockCode, stockName, 10, 150, member);

        given(membersRepository.findById(memberId)).willReturn(Optional.of(member));
        given(portfoliosRepository.findByMembersIdAndStockCode(memberId, stockCode))
                .willReturn(Optional.of(portfolio));

        // when
        portfoliosService.updateForBuy(memberId, stockCode, stockName, quantity, price);

        // then
        assertThat(portfolio.getQuantity()).isEqualTo(15);
        assertThat(portfolio.getAvgPrice()).isEqualTo((10 * 150 + 5 * 200) / 15);
        verify(portfoliosRepository).save(portfolio);
    }

    @Test
    void updateForBuy_새로운종목_포트폴리오생성() {
        // given
        Long memberId = 1L;
        String stockCode = "GOOG";
        String stockName = "구글";
        int quantity = 3;
        int price = 180;

        Members member =
                new Members(
                        memberId,
                        "test@example.com",
                        "testUser",
                        "google",
                        "profile.png",
                        30000000,
                        0,
                        LocalDateTime.now());

        given(membersRepository.findById(memberId)).willReturn(Optional.of(member));
        given(portfoliosRepository.findByMembersIdAndStockCode(memberId, stockCode))
                .willReturn(Optional.empty());

        // when
        portfoliosService.updateForBuy(memberId, stockCode, stockName, quantity, price);

        // then
        verify(portfoliosRepository).save(any(Portfolios.class));
    }

    @Test
    void updateForSell_수량감소() {
        // given
        Long memberId = 1L;
        String stockCode = "AAPL";
        int quantityToSell = 5;

        Members member =
                new Members(
                        memberId,
                        "test@example.com",
                        "testUser",
                        "google",
                        "profile.png",
                        30000000,
                        0,
                        LocalDateTime.now());

        Portfolios portfolio = new Portfolios(stockCode, "애플", 10, 150, member);

        given(membersRepository.findById(memberId)).willReturn(Optional.of(member));
        given(portfoliosRepository.findByMembersIdAndStockCode(memberId, stockCode))
                .willReturn(Optional.of(portfolio));

        // when
        portfoliosService.updateForSell(memberId, stockCode, quantityToSell);

        // then
        assertThat(portfolio.getQuantity()).isEqualTo(5);
        verify(portfoliosRepository, never()).delete(any());
        verify(portfoliosRepository, never()).save(any());
    }

    @Test
    void updateForSell_전량매도_삭제확인() {
        // given
        Long memberId = 1L;
        String stockCode = "AAPL";
        int quantityToSell = 10;

        Members member =
                new Members(
                        memberId,
                        "test@example.com",
                        "testUser",
                        "google",
                        "profile.png",
                        30000000,
                        0,
                        LocalDateTime.now());

        Portfolios portfolio = new Portfolios(stockCode, "애플", 10, 150, member);

        given(membersRepository.findById(memberId)).willReturn(Optional.of(member));
        given(portfoliosRepository.findByMembersIdAndStockCode(memberId, stockCode))
                .willReturn(Optional.of(portfolio));

        // when
        portfoliosService.updateForSell(memberId, stockCode, quantityToSell);

        // then
        assertThat(portfolio.getQuantity()).isEqualTo(0);
        verify(portfoliosRepository).delete(portfolio);
    }

    @Test
    void updateForSell_보유주식_없을경우() {
        // given
        Long memberId = 1L;
        String stockCode = "AAPL";
        int quantity = 5;

        // 멤버는 존재
        Members member =
                new Members(
                        memberId,
                        "test@example.com",
                        "testUser",
                        "google",
                        "profile.png",
                        30000000,
                        0,
                        LocalDateTime.now());
        when(membersRepository.findById(memberId)).thenReturn(Optional.of(member));

        // 포트폴리오는 없음
        when(portfoliosRepository.findByMembersIdAndStockCode(memberId, stockCode))
                .thenReturn(Optional.empty());

        // when & then
        assertThrows(
                NotFoundPortfolioException.class,
                () -> {
                    portfoliosService.updateForSell(memberId, stockCode, quantity);
                });
    }
}
