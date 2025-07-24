package io.gaboja9.mockstock.domain.orders.controller;

import io.gaboja9.mockstock.domain.auth.dto.MembersDetails;
import io.gaboja9.mockstock.domain.orders.dto.request.OrdersMarketTypeRequestDto;
import io.gaboja9.mockstock.domain.orders.dto.response.OrderResponseDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

@Tag(name = "주문 컨트롤러", description = "주문 api입니다.")
@RequestMapping("/orders")
public interface OrdersControllerSpec {

    @Operation(
            summary = "주식을 시장가로 매수합니다.",
            description = "주식을 시장가로 매수하고 매수 결과를 불러옵니다.",
            responses =
                    @ApiResponse(
                            responseCode = "201",
                            description = "성공적으로 주식을 매수했습니다.",
                            content =
                                    @Content(
                                            mediaType = "application/json",
                                            schema =
                                                    @Schema(
                                                            implementation =
                                                                    OrderResponseDto.class))))
    @PostMapping("/market/buy")
    ResponseEntity<OrderResponseDto> executeMarketBuy(
            @Valid @RequestBody OrdersMarketTypeRequestDto requestDto,
            @AuthenticationPrincipal MembersDetails membersDetails);

    @Operation(
            summary = "주식을 시장가로 매도합니다.",
            description = "주식을 시장가로 매도하고 매도 결과를 불러옵니다.",
            responses =
                    @ApiResponse(
                            responseCode = "201",
                            description = "성공적으로 주식을 매도했습니다.",
                            content =
                                    @Content(
                                            mediaType = "application/json",
                                            schema =
                                                    @Schema(
                                                            implementation =
                                                                    OrderResponseDto.class))))
    @PostMapping("/market/sell")
    ResponseEntity<OrderResponseDto> executeMarketSell(
            @Valid @RequestBody OrdersMarketTypeRequestDto requestDto,
            @AuthenticationPrincipal MembersDetails membersDetails);
}
