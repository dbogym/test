package io.gaboja9.mockstock.domain.stock.controller;

import io.gaboja9.mockstock.domain.stock.dto.StockResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

import org.springframework.http.ResponseEntity;

import java.util.List;

@Tag(name = "주식 관리", description = "주식 관련 API")
public interface StockControllerSpec {

    @Operation(
            summary = "전체 주식 목록 조회",
            description = "등록된 모든 주식의 목록을 조회합니다.",
            tags = {"주식 관리"})
    @ApiResponses({
        @ApiResponse(
                responseCode = "200",
                description = "주식 목록 조회 성공",
                content =
                        @Content(
                                mediaType = "application/json",
                                array =
                                        @ArraySchema(
                                                schema =
                                                        @Schema(
                                                                implementation =
                                                                        StockResponse.class)),
                                examples =
                                        @ExampleObject(
                                                name = "주식 목록 조회 성공",
                                                value =
                                                        """
                                                        [
                                                          {
                                                            "stockCode": "005930",
                                                            "stockName": "삼성전자"
                                                          },
                                                          {
                                                            "stockCode": "035420",
                                                            "stockName": "NAVER"
                                                          },
                                                          {
                                                            "stockCode": "035720",
                                                            "stockName": "카카오"
                                                          },
                                                          {
                                                            "stockCode": "259960",
                                                            "stockName": "크래프톤"
                                                          },
                                                          {
                                                            "stockCode": "068270",
                                                            "stockName": "셀트리온"
                                                          }
                                                        ]
                                                        """))),
        @ApiResponse(
                responseCode = "500",
                description = "서버 내부 오류",
                content =
                        @Content(
                                mediaType = "application/json",
                                schema = @Schema(implementation = ApiResponse.class),
                                examples =
                                        @ExampleObject(
                                                name = "서버 오류",
                                                value =
                                                        """
                                                        {
                                                          "success": false,
                                                          "errorCode": "INTERNAL_SERVER_ERROR",
                                                          "message": "서버 내부 오류가 발생했습니다.",
                                                          "data": null
                                                        }
                                                        """)))
    })
    ResponseEntity<List<StockResponse>> getAllStocks();
}
