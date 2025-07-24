package io.gaboja9.mockstock.domain.orders.entity;

import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.trades.entity.TradeType;

import jakarta.persistence.*;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Getter
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Orders {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String stockCode;
    private String stockName;

    @Enumerated(EnumType.STRING)
    private OrderType orderType; // MARKET, LIMIT

    @Enumerated(EnumType.STRING)
    private TradeType tradeType; // BUY, SELL

    private int quantity;
    private int price; // 지정가인 경우 사용

    @Enumerated(EnumType.STRING)
    private OrderStatus status; // PENDING, EXECUTED, CANCELLED

    private LocalDateTime executedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "members_id")
    private Members members;

    public Orders(
            String stockCode,
            String stockName,
            OrderType orderType,
            TradeType tradeType,
            int quantity,
            int price,
            Members members) {
        this.stockCode = stockCode;
        this.stockName = stockName;
        this.orderType = orderType;
        this.tradeType = tradeType;
        this.quantity = quantity;
        this.price = price;
        this.members = members;
        this.status = OrderStatus.PENDING;
    }

    public void execute() {
        this.status = OrderStatus.EXECUTED;
        this.executedAt = LocalDateTime.now();
    }
}
