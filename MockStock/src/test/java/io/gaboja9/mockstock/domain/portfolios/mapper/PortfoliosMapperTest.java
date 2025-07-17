// package io.gaboja9.mockstock.domain.portfolios.mapper;
//
// import static org.assertj.core.api.Assertions.assertThat;
// import static org.assertj.core.api.Assertions.assertThatThrownBy;
// import static org.mockito.BDDMockito.given;
//
// import io.gaboja9.mockstock.domain.portfolios.dto.response.PortfolioResponseDto;
// import io.gaboja9.mockstock.domain.portfolios.entity.Portfolios;
// import io.gaboja9.mockstock.global.Influx.InfluxQueryService;
//
// import org.junit.jupiter.api.Test;
// import org.junit.jupiter.api.extension.ExtendWith;
// import org.mockito.InjectMocks;
// import org.mockito.Mock;
// import org.mockito.junit.jupiter.MockitoExtension;
//
// @ExtendWith(MockitoExtension.class)
// class PortfoliosMapperTest {
//
//    @InjectMocks private PortfoliosMapper portfoliosMapper;
//
//    @Mock private InfluxQueryService influxQueryService;
//
//    @Test
//    void toDto_정상작동() {
//        // given
//        Portfolios p = new Portfolios(1L, "AAPL", "애플", 10, 150);
//        int currentPrice = 160;
//
//        given(influxQueryService.getCurrentPrice("AAPL")).willReturn(currentPrice);
//
//        // when
//        PortfolioResponseDto result = portfoliosMapper.toDto(p);
//
//        // then
//        assertThat(result.getStockCode()).isEqualTo("AAPL");
//        assertThat(result.getStockName()).isEqualTo("애플");
//        assertThat(result.getQuantity()).isEqualTo(10);
//        assertThat(result.getAvgPrice()).isEqualTo(150);
//        assertThat(result.getCurrentPrice()).isEqualTo(160);
//        assertThat(result.getEvaluationAmount()).isEqualTo(1600); // 160 * 10
//        assertThat(result.getProfit()).isEqualTo(100); // (160 - 150) * 10
//        assertThat(result.getProfitRate()).isEqualTo(6.67); // (100 / 1500) * 100
//    }
//
//    @Test
//    void toDto_투자금이_없을경우() {
//        // given
//        Portfolios p = new Portfolios(2L, "TSLA", "테슬라", 0, 0);
//        given(influxQueryService.getCurrentPrice("TSLA")).willReturn(200);
//
//        // when
//        PortfolioResponseDto result = portfoliosMapper.toDto(p);
//
//        // then
//        assertThat(result.getEvaluationAmount()).isEqualTo(0);
//        assertThat(result.getProfit()).isEqualTo(0);
//        assertThat(result.getProfitRate()).isEqualTo(0.00);
//    }
//
//    @Test
//    void toDto_에러발생() {
//        // given
//        Portfolios p = new Portfolios(2L, "TSLA", "테슬라", 0, 0);
//        given(influxQueryService.getCurrentPrice("TSLA"))
//                .willThrow(new RuntimeException("Influx error"));
//
//        // when & then
//        assertThatThrownBy(() -> portfoliosMapper.toDto(p))
//                .isInstanceOf(RuntimeException.class)
//                .hasMessageContaining("Influx error");
//    }
// }
