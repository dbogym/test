package io.gaboja9.mockstock.domain.trades.entity;

import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.global.common.BaseEntity;

import jakarta.persistence.*;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Trades extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String stockCode;

    private String stockName;

    @Enumerated(EnumType.STRING)
    private TradeType tradeType;

    private int quantity;

    private int price;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "members_id")
    private Members members;

    // 테스트용 생성자
    public Trades(
            String stockCode,
            String stockName,
            TradeType tradeType,
            int quantity,
            int price,
            Members members) {
        this.stockCode = stockCode;
        this.stockName = stockName;
        this.tradeType = tradeType;
        this.quantity = quantity;
        this.price = price;
        this.members = members;
    }
}
