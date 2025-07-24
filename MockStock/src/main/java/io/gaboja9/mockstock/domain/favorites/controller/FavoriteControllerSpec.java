package io.gaboja9.mockstock.domain.favorites.controller;

import io.gaboja9.mockstock.domain.auth.dto.MembersDetails;
import io.gaboja9.mockstock.domain.favorites.dto.response.FavoriteResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.List;

@Tag(name = "관심종목 관리", description = "관심종목 관련 API")
public interface FavoriteControllerSpec {

    @Tag(name = "관심종목 관리", description = "관심종목 등록, 삭제, 조회 API")
    public interface FavoritesApi {

        @Operation(
                summary = "관심종목 등록",
                description = "사용자가 특정 주식을 관심종목으로 등록합니다.",
                tags = {"관심종목 관리"})
        @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "관심종목 등록 성공",
                    content =
                            @Content(
                                    schema = @Schema(implementation = FavoriteResponse.class),
                                    examples =
                                            @ExampleObject(
                                                    name = "성공 응답",
                                                    value =
                                                            """
                                                            {
                                                              "favoriteId": 1,
                                                              "memberId": 123,
                                                              "memberNickname": "투자고수",
                                                              "stockName": "삼성전자",
                                                              "stockCode": "005930",
                                                              "createdAt": "2025-07-17T10:30:00",
                                                              "updatedAt": "2025-07-17T10:30:00"
                                                            }
                                                            """))),
            @ApiResponse(
                    responseCode = "404",
                    description = "존재하지 않는 주식",
                    content =
                            @Content(
                                    schema = @Schema(implementation = ApiResponse.class),
                                    examples =
                                            @ExampleObject(
                                                    name = "주식 조회 실패",
                                                    value =
                                                            """
                                                            {
                                                                  "message": "주식을 찾을 수 없습니다. ID: 0059300",
                                                                  "code": "STOCK-001",
                                                                  "status": 404,
                                                                  "timestamp": "2025-07-18T09:43:00.863211"
                                                            }
                                                            """))),
            @ApiResponse(
                    responseCode = "400",
                    description = "이미 관심종목으로 등록된 주식",
                    content =
                            @Content(
                                    schema = @Schema(implementation = ApiResponse.class),
                                    examples =
                                            @ExampleObject(
                                                    name = "중복 등록",
                                                    value =
                                                            """
                                                            {
                                                              "message": "Stock code: 005930",
                                                              "code": "FAVORITE-002",
                                                              "status": 400,
                                                              "timestamp": "2025-07-18T09:41:40.482628"
                                                            }
                                                            """)))
        })
        ResponseEntity<FavoriteResponse> addFavorite(
                @Parameter(hidden = true) @AuthenticationPrincipal MembersDetails membersDetails,
                @Parameter(
                                name = "stockCode",
                                description = "주식 코드 (6자리 숫자)",
                                required = true,
                                example = "005930",
                                schema = @Schema(type = "string", pattern = "\\d{6}"))
                        @PathVariable
                        String stockCode);

        @Operation(
                summary = "관심종목 해제",
                description = "사용자가 등록한 관심종목을 해제합니다.",
                tags = {"관심종목 관리"})
        @ApiResponses({
            @ApiResponse(responseCode = "200", description = "관심종목 해제 성공"),
            @ApiResponse(
                    responseCode = "404",
                    description = "관심종목을 찾을 수 없음",
                    content =
                            @Content(
                                    schema = @Schema(implementation = ApiResponse.class),
                                    examples =
                                            @ExampleObject(
                                                    name = "관심종목 조회 실패",
                                                    value =
                                                            """
                                                            "message": "주식을 찾을 수 없습니다. ID: 0059300",
                                                            "code": "STOCK-001",
                                                            "status": 404,
                                                            "timestamp": "2025-07-18T09:46:14.289283"
                                                            """)))
        })
        ResponseEntity<Void> removeFavorite(
                @Parameter(hidden = true) @AuthenticationPrincipal MembersDetails membersDetails,
                @Parameter(
                                name = "stockCode",
                                description = "주식 코드 (6자리 숫자)",
                                required = true,
                                example = "005930",
                                schema = @Schema(type = "string", pattern = "\\d{6}"))
                        @PathVariable
                        String stockCode);

        @Operation(
                summary = "내 관심종목 목록 조회",
                description = "로그인한 사용자의 관심종목 목록을 최신 등록일순으로 조회합니다.",
                tags = {"관심종목 관리"})
        @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "관심종목 목록 조회 성공",
                    content =
                            @Content(
                                    array =
                                            @ArraySchema(
                                                    schema =
                                                            @Schema(
                                                                    implementation =
                                                                            FavoriteResponse
                                                                                    .class)),
                                    examples =
                                            @ExampleObject(
                                                    name = "관심종목 목록",
                                                    value =
                                                            """
                                                            [
                                                              {
                                                                "memberId": 2,
                                                                "stockName": "삼성전자",
                                                                "stockCode": "005930"
                                                              },
                                                              {
                                                                "memberId": 2,
                                                                "stockName": "에코프로비엠",
                                                                "stockCode": "247540"
                                                              }
                                                            ]
                                                            """))),
            @ApiResponse(
                    responseCode = "404",
                    description = "존재하지 않는 회원",
                    content =
                            @Content(
                                    schema = @Schema(implementation = ApiResponse.class),
                                    examples =
                                            @ExampleObject(
                                                    name = "관심종목 조회 실패",
                                                    value =
                                                            """
                                                            "message": "멤버를 찾을 수 없습니다. ID: 99999",
                                                            "code": "MEMBER-001",
                                                            "status": 404,
                                                            "timestamp": "2025-07-18T09:46:14.289283"
                                                            """)))
        })
        ResponseEntity<List<FavoriteResponse>> getMemberFavorites(
                @Parameter(hidden = true) @AuthenticationPrincipal MembersDetails membersDetails);
    }
}
