package io.gaboja9.mockstock.domain.stock.measurement;

import com.influxdb.annotations.Column;
import com.influxdb.annotations.Measurement;

import lombok.Data;

import java.time.Instant;

@Data
@Measurement(name = "stock_daily")
public class DailyStockPrice {

    @Column(timestamp = true)
    private Instant timestamp;

    @Column(tag = true)
    private String stockCode;

    @Column private Long maxPrice;

    @Column private Long minPrice;

    @Column private Long accumTrans;

    @Column private Long openPrice;

    @Column private Long closePrice;
}
