package io.gaboja9.mockstock.domain.portfolios.service;

import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.members.exception.NotFoundMemberException;
import io.gaboja9.mockstock.domain.members.repository.MembersRepository;
import io.gaboja9.mockstock.domain.portfolios.dto.PortfoliosSummary;
import io.gaboja9.mockstock.domain.portfolios.dto.response.PortfolioResponseDto;
import io.gaboja9.mockstock.domain.portfolios.dto.response.PortfoliosResponseDto;
import io.gaboja9.mockstock.domain.portfolios.entity.Portfolios;
import io.gaboja9.mockstock.domain.portfolios.mapper.PortfoliosMapper;
import io.gaboja9.mockstock.domain.portfolios.repository.PortfoliosRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class PortfoliosService {

    private final PortfoliosRepository portfoliosRepository;
    private final PortfoliosMapper portfoliosMapper;
    private final MembersRepository membersRepository;

    @Transactional(readOnly = true)
    public PortfoliosResponseDto getPortfolios(Long memberId) {
        List<Portfolios> portfoliosList = portfoliosRepository.findByMembersId(memberId);

        List<PortfolioResponseDto> dtoList = new ArrayList<>();
        for (Portfolios p : portfoliosList) {
            dtoList.add(portfoliosMapper.toDto(p));
        }

        PortfoliosSummary summary = calculateSummary(dtoList);

        int cashBalance =
                membersRepository
                        .findById(memberId)
                        .orElseThrow(() -> new NotFoundMemberException(memberId))
                        .getCashBalance();

        return PortfoliosResponseDto.builder()
                .cashBalance(cashBalance)
                .totalEvaluationAmount(summary.getTotalEvaluationAmount())
                .totalProfit(summary.getTotalProfit())
                .totalProfitRate(summary.getTotalProfitRate())
                .portfolios(dtoList)
                .build();
    }

    public PortfoliosSummary calculateSummary(List<PortfolioResponseDto> dtoList) {
        int totalEvaluationAmount = 0;
        int totalProfit = 0;
        int totalInvestment = 0;

        for (PortfolioResponseDto dto : dtoList) {
            totalEvaluationAmount += dto.getEvaluationAmount();
            totalProfit += dto.getProfit();
            totalInvestment += dto.getAvgPrice() * dto.getQuantity();
        }

        double totalProfitRate =
                totalInvestment == 0
                        ? 0.00
                        : Math.round((double) totalProfit / totalInvestment * 100 * 100) / 100.0;

        return PortfoliosSummary.builder()
                .totalEvaluationAmount(totalEvaluationAmount)
                .totalProfit(totalProfit)
                .totalProfitRate(totalProfitRate)
                .build();
    }

    @Transactional
    public void remove(Long memberId) {

        Members findMember =
                membersRepository
                        .findById(memberId)
                        .orElseThrow(() -> new NotFoundMemberException(memberId));

        portfoliosRepository.deleteByMembersId(findMember.getId());
    }
}
