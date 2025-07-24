package io.gaboja9.mockstock.domain.orders.controller;

import io.gaboja9.mockstock.domain.auth.dto.MembersDetails;
import io.gaboja9.mockstock.domain.orders.dto.request.OrdersMarketTypeRequestDto;
import io.gaboja9.mockstock.domain.orders.dto.response.OrderResponseDto;
import io.gaboja9.mockstock.domain.orders.service.OrdersService;

import jakarta.validation.Valid;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/orders")
@RequiredArgsConstructor
public class OrdersController implements OrdersControllerSpec {

    private final OrdersService ordersService;

    @PostMapping("/market/buy")
    public ResponseEntity<OrderResponseDto> executeMarketBuy(
            @Valid @RequestBody OrdersMarketTypeRequestDto requestDto,
            @AuthenticationPrincipal MembersDetails membersDetails) {

        Long id = membersDetails.getId();

        OrderResponseDto responseDto = ordersService.executeMarketBuyOrders(id, requestDto);

        return ResponseEntity.status(HttpStatus.CREATED).body(responseDto);
    }

    @PostMapping("/market/sell")
    public ResponseEntity<OrderResponseDto> executeMarketSell(
            @Valid @RequestBody OrdersMarketTypeRequestDto requestDto,
            @AuthenticationPrincipal MembersDetails membersDetails) {

        Long id = membersDetails.getId();

        OrderResponseDto responseDto = ordersService.executeMarketSellOrders(id, requestDto);

        return ResponseEntity.status(HttpStatus.CREATED).body(responseDto);
    }
}
