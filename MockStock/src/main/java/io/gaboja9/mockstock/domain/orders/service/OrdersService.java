package io.gaboja9.mockstock.domain.orders.service;

import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.members.exception.NotFoundMemberException;
import io.gaboja9.mockstock.domain.members.repository.MembersRepository;
import io.gaboja9.mockstock.domain.notifications.service.NotificationsService;
import io.gaboja9.mockstock.domain.orders.dto.request.OrdersMarketTypeRequestDto;
import io.gaboja9.mockstock.domain.orders.dto.response.OrderResponseDto;
import io.gaboja9.mockstock.domain.orders.entity.OrderType;
import io.gaboja9.mockstock.domain.orders.entity.Orders;
import io.gaboja9.mockstock.domain.orders.exception.InvalidSellQuantityException;
import io.gaboja9.mockstock.domain.orders.exception.NotEnoughCashException;
import io.gaboja9.mockstock.domain.orders.repository.OrdersRepository;
import io.gaboja9.mockstock.domain.portfolios.entity.Portfolios;
import io.gaboja9.mockstock.domain.portfolios.exception.NotFoundPortfolioException;
import io.gaboja9.mockstock.domain.portfolios.repository.PortfoliosRepository;
import io.gaboja9.mockstock.domain.portfolios.service.PortfoliosService;
import io.gaboja9.mockstock.domain.trades.entity.TradeType;
import io.gaboja9.mockstock.domain.trades.entity.Trades;
import io.gaboja9.mockstock.domain.trades.repository.TradesRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class OrdersService {

    private final MembersRepository membersRepository;
    private final OrdersRepository ordersRepository;
    private final TradesRepository tradesRepository;
    private final PortfoliosService portfoliosService;
    private final PortfoliosRepository portfoliosRepository;
    private final NotificationsService notificationsService;

    @Transactional
    public OrderResponseDto executeMarketBuyOrders(Long memberId, OrdersMarketTypeRequestDto dto) {

        Members findMember =
                membersRepository
                        .findById(memberId)
                        .orElseThrow(() -> new NotFoundMemberException(memberId));

        String stockCode = dto.getStockCode();
        String stockName = dto.getStockName();
        int currentPrice = 100000; // TODO: 시장가 받아오기
        int quantity = dto.getQuantity();
        int totalPrice = currentPrice * quantity;
        int cashBalance = findMember.getCashBalance();

        if (cashBalance < totalPrice) {
            throw new NotEnoughCashException(cashBalance);
        }

        Orders order =
                new Orders(
                        stockCode,
                        stockName,
                        OrderType.MARKET,
                        TradeType.BUY,
                        quantity,
                        currentPrice,
                        findMember);
        order.execute();
        ordersRepository.save(order);

        Trades trades =
                new Trades(stockCode, stockName, TradeType.BUY, quantity, currentPrice, findMember);
        tradesRepository.save(trades);

        findMember.setCashBalance(cashBalance - totalPrice);

        portfoliosService.updateForBuy(memberId, stockCode, stockName, quantity, currentPrice);

        try {
            notificationsService.sendTradeNotification(
                    memberId, stockCode, stockName, TradeType.BUY, quantity, currentPrice);
        } catch (Exception e) {
            log.error("매수 알림 발송 실패 - 사용자: {}, 종목: {}", memberId, stockName, e);
        }

        return OrderResponseDto.builder()
                .executed(true)
                .message("시장가 매수 완료")
                .price(currentPrice)
                .build();
    }

    @Transactional
    public OrderResponseDto executeMarketSellOrders(Long memberId, OrdersMarketTypeRequestDto dto) {

        Members member =
                membersRepository
                        .findById(memberId)
                        .orElseThrow(() -> new NotFoundMemberException(memberId));

        String stockCode = dto.getStockCode();
        String stockName = dto.getStockName();
        int quantity = dto.getQuantity();

        Portfolios portfolio =
                portfoliosRepository
                        .findByMembersIdAndStockCode(memberId, stockCode)
                        .orElseThrow(() -> new NotFoundPortfolioException());

        if (portfolio.getQuantity() < quantity) {
            throw new InvalidSellQuantityException(quantity);
        }

        int currentPrice = 100000; // TODO: 실제 시장가 서비스 연동
        int totalAmount = currentPrice * quantity;

        Orders order =
                new Orders(
                        stockCode,
                        stockName,
                        OrderType.MARKET,
                        TradeType.SELL,
                        quantity,
                        currentPrice,
                        member);
        order.execute();
        ordersRepository.save(order);

        Trades trades =
                new Trades(stockCode, stockName, TradeType.SELL, quantity, currentPrice, member);
        tradesRepository.save(trades);

        portfoliosService.updateForSell(memberId, stockCode, quantity);

        member.setCashBalance(member.getCashBalance() + totalAmount);

        try {
            notificationsService.sendTradeNotification(
                    memberId, stockCode, stockName, TradeType.SELL, quantity, currentPrice);
        } catch (Exception e) {
            log.error("매도 알림 발송 실패 - 사용자: {}, 종목: {}", memberId, stockName, e);
        }

        return OrderResponseDto.builder()
                .executed(true)
                .message("시장가 매도 완료")
                .price(currentPrice)
                .build();
    }
}
