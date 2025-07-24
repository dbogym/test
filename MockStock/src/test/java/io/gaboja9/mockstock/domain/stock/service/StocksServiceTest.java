package io.gaboja9.mockstock.domain.stock.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import io.gaboja9.mockstock.domain.stock.dto.StockResponse;
import io.gaboja9.mockstock.domain.stock.entity.Stocks;
import io.gaboja9.mockstock.domain.stock.mapper.StocksMapper;
import io.gaboja9.mockstock.domain.stock.repository.StocksRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.List;

@ExtendWith(MockitoExtension.class)
@DisplayName("StocksService 테스트")
class StocksServiceTest {

    @Mock private StocksRepository stocksRepository;

    @Mock private StocksMapper stocksMapper;

    @InjectMocks private StocksService stocksService;

    @BeforeEach
    void setUp() {
        reset(stocksRepository);
    }

    @Test
    @DisplayName("초기 데이터가 없을 때 initData()는 20개의 주식 데이터를 생성한다")
    void initData_success() {
        // given
        when(stocksRepository.count()).thenReturn(0L);
        when(stocksRepository.save(any(Stocks.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // when
        stocksService.initData();

        // then
        verify(stocksRepository, times(1)).count();
        verify(stocksRepository, times(20)).save(any(Stocks.class));

        // 특정 주식들이 저장되는지 확인
        verify(stocksRepository)
                .save(
                        argThat(
                                stock ->
                                        "삼성전자".equals(stock.getStockName())
                                                && "005930".equals(stock.getStockCode())));
        verify(stocksRepository)
                .save(
                        argThat(
                                stock ->
                                        "NAVER".equals(stock.getStockName())
                                                && "035420".equals(stock.getStockCode())));
        verify(stocksRepository)
                .save(
                        argThat(
                                stock ->
                                        "카카오".equals(stock.getStockName())
                                                && "035720".equals(stock.getStockCode())));
    }

    @Test
    @DisplayName("기존 데이터가 있을 때 initData()는 새로운 데이터를 생성하지 않는다")
    void initData_dataExist() {
        // given
        when(stocksRepository.count()).thenReturn(5L);

        // when
        stocksService.initData();

        // then
        verify(stocksRepository, times(1)).count();
        verify(stocksRepository, never()).save(any(Stocks.class));
    }

    @Test
    @DisplayName("getAllStocks()는 모든 주식 목록을 반환한다")
    void getAllStocks_success() {
        // given
        List<Stocks> expectedStocks =
                Arrays.asList(
                        new Stocks("삼성전자", "005930"),
                        new Stocks("NAVER", "035420"),
                        new Stocks("카카오", "035720"));

        List<StockResponse> expectedStockResponses =
                Arrays.asList(
                        StockResponse.builder().stockCode("005930").stockName("삼성전자").build(),
                        StockResponse.builder().stockCode("035420").stockName("NAVER").build(),
                        StockResponse.builder().stockCode("035720").stockName("카카오").build());

        when(stocksRepository.findAll()).thenReturn(expectedStocks);
        when(stocksMapper.toDtoList(expectedStocks)).thenReturn(expectedStockResponses);

        // when
        List<StockResponse> actualStocks = stocksService.getAllStocks();

        // then
        assertThat(actualStocks.get(0).getStockCode()).isEqualTo("005930");
        assertThat(actualStocks.get(0).getStockName()).isEqualTo("삼성전자");

        assertThat(actualStocks.get(1).getStockCode()).isEqualTo("035420");
        assertThat(actualStocks.get(1).getStockName()).isEqualTo("NAVER");

        assertThat(actualStocks.get(2).getStockCode()).isEqualTo("035720");
        assertThat(actualStocks.get(2).getStockName()).isEqualTo("카카오");

        verify(stocksRepository, times(1)).findAll();
    }

    @Test
    @DisplayName("initData()에서 생성되는 모든 주식의 이름과 코드를 검증한다")
    void initData_ShouldCreateCorrectStockData() {
        // given
        when(stocksRepository.count()).thenReturn(0L);
        when(stocksRepository.save(any(Stocks.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // when
        stocksService.initData();

        // then
        // 모든 예상 주식 데이터 검증
        String[][] expectedStocks = {
            {"삼성전자", "005930"},
            {"에코프로비엠", "247540"},
            {"현대차", "005380"},
            {"NAVER", "035420"},
            {"카카오", "035720"},
            {"크래프톤", "259960"},
            {"셀트리온", "068270"},
            {"한미약품", "128940"},
            {"SK이노베이션", "096770"},
            {"LG화학", "051910"},
            {"POSCO홀딩스", "005490"},
            {"SK텔레콤", "017670"},
            {"KB금융", "105560"},
            {"카카오뱅크", "323410"},
            {"이마트", "139480"},
            {"CJ대한통운", "000120"},
            {"대한항공", "003490"},
            {"한국조선해양", "009540"},
            {"DL이앤씨", "375500"},
            {"삼성SDI", "006400"}
        };

        for (String[] stockData : expectedStocks) {
            verify(stocksRepository)
                    .save(
                            argThat(
                                    stock ->
                                            stockData[0].equals(stock.getStockName())
                                                    && stockData[1].equals(stock.getStockCode())));
        }
    }
}
