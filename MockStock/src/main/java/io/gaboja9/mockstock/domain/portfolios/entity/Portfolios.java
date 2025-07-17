package io.gaboja9.mockstock.domain.portfolios.entity;

import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.global.common.BaseEntity;

import jakarta.persistence.*;

import lombok.*;

@Getter
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Portfolios extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String stockName;

    private String stockCode;

    private int quantity;

    private int avgPrice;

    private boolean deleted = false;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "members_id")
    private Members members;

    // 테스트용 생성자
    public Portfolios(Long id, String stockCode, String stockName, int quantity, int avgPrice) {
        this.id = id;
        this.stockCode = stockCode;
        this.stockName = stockName;
        this.quantity = quantity;
        this.avgPrice = avgPrice;
    }
}
