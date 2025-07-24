package io.gaboja9.mockstock.domain.stock.service;

import io.gaboja9.mockstock.domain.stock.dto.StockResponse;
import io.gaboja9.mockstock.domain.stock.entity.Stocks;
import io.gaboja9.mockstock.domain.stock.mapper.StocksMapper;
import io.gaboja9.mockstock.domain.stock.repository.StocksRepository;

import jakarta.annotation.PostConstruct;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class StocksService {

    private final StocksRepository stocksRepository;
    private final StocksMapper stocksMapper;

    // 초기 데이터 생성 배포 서버에서는 직접 넣어줄 예정
    @PostConstruct
    public void initData() {
        if (stocksRepository.count() == 0) {
            stocksRepository.save(new Stocks("삼성전자", "005930"));
            stocksRepository.save(new Stocks("에코프로비엠", "247540"));
            stocksRepository.save(new Stocks("현대차", "005380"));
            stocksRepository.save(new Stocks("NAVER", "035420"));
            stocksRepository.save(new Stocks("카카오", "035720"));
            stocksRepository.save(new Stocks("크래프톤", "259960"));
            stocksRepository.save(new Stocks("셀트리온", "068270"));
            stocksRepository.save(new Stocks("한미약품", "128940"));
            stocksRepository.save(new Stocks("SK이노베이션", "096770"));
            stocksRepository.save(new Stocks("LG화학", "051910"));
            stocksRepository.save(new Stocks("POSCO홀딩스", "005490"));
            stocksRepository.save(new Stocks("SK텔레콤", "017670"));
            stocksRepository.save(new Stocks("KB금융", "105560"));
            stocksRepository.save(new Stocks("카카오뱅크", "323410"));
            stocksRepository.save(new Stocks("이마트", "139480"));
            stocksRepository.save(new Stocks("CJ대한통운", "000120"));
            stocksRepository.save(new Stocks("대한항공", "003490"));
            stocksRepository.save(new Stocks("한국조선해양", "009540"));
            stocksRepository.save(new Stocks("DL이앤씨", "375500"));
            stocksRepository.save(new Stocks("삼성SDI", "006400"));
        }
    }

    public List<StockResponse> getAllStocks() {

        return stocksMapper.toDtoList(stocksRepository.findAll());
    }
}
