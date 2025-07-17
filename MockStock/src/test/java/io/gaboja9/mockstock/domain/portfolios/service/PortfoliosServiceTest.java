package io.gaboja9.mockstock.domain.portfolios.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.members.exception.NotFoundMemberException;
import io.gaboja9.mockstock.domain.members.repository.MembersRepository;
import io.gaboja9.mockstock.domain.portfolios.dto.response.PortfolioResponseDto;
import io.gaboja9.mockstock.domain.portfolios.dto.response.PortfoliosResponseDto;
import io.gaboja9.mockstock.domain.portfolios.entity.Portfolios;
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

        Portfolios p1 = new Portfolios(1L, "AAPL", "애플", 10, 150);
        Portfolios p2 = new Portfolios(2L, "TSLA", "테슬라", 5, 200);

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
}
