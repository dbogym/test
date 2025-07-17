package io.gaboja9.mockstock.global.Influx;

import com.influxdb.client.InfluxDBClient;
import com.influxdb.client.InfluxDBClientFactory;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration // 이 클래스가 설정 파일임을 스프링에 알립니다.
public class InfluxConfig {

    // application.yml 파일에서 influxdb 접속 정보를 가져옵니다.
    @Value("${spring.influx.url}")
    private String url;

    @Value("${spring.influx.token}")
    private String token;

    @Value("${spring.influx.org}")
    private String org;

    @Bean
    @Qualifier("dailyInfluxDBClient")
    public InfluxDBClient dailyInfluxDBClient(
            @Value("${spring.influx.bucket.daily}") String dailyBucket) {
        return InfluxDBClientFactory.create(url, token.toCharArray(), org, dailyBucket);
    }

    // Minute Bucket Client
    @Bean
    @Qualifier("minuteInfluxDBClient")
    public InfluxDBClient minuteInfluxDBClient(
            @Value("${spring.influx.bucket.minute}") String minuteBucket) {
        return InfluxDBClientFactory.create(url, token.toCharArray(), org, minuteBucket);
    }
}
