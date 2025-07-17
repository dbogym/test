package io.gaboja9.mockstock;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class MockStockApplication {

    public static void main(String[] args) {
        SpringApplication.run(MockStockApplication.class, args);
    }
}