package io.gaboja9.mockstock.domain.trades.service;

import io.gaboja9.mockstock.domain.trades.dto.request.TradesRequestDto;
import io.gaboja9.mockstock.domain.trades.dto.response.TradesResponseDto;
import io.gaboja9.mockstock.domain.trades.entity.Trades;
import io.gaboja9.mockstock.domain.trades.mapper.TradesMapper;
import io.gaboja9.mockstock.domain.trades.repository.TradesRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class TradesService {

    private final TradesRepository tradesRepository;
    private final TradesMapper tradesMapper;

    @Transactional(readOnly = true)
    public Page<TradesResponseDto> getTrades(Long membersId, Pageable pageable) {
        Page<Trades> tradesPage = tradesRepository.findByMembersId(membersId, pageable);
        return tradesPage.map(tradesMapper::toDto);
    }

    @Transactional(readOnly = true)
    public Page<TradesResponseDto> getTradesWithOption(
            Long membersId, TradesRequestDto dto, Pageable pageable) {
        LocalDateTime start = dto.getStartDate().atStartOfDay();
        LocalDateTime end = dto.getEndDate().atTime(23, 59, 59, 999_999_999);

        Page<Trades> page =
                tradesRepository.findByStockCodeOrStockNameAndCreatedAtBetween(
                        dto.getStockCode(), dto.getStockName(), start, end, membersId, pageable);

        return page.map(tradesMapper::toDto);
    }
}
