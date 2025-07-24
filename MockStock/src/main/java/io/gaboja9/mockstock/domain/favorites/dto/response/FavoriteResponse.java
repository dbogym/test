package io.gaboja9.mockstock.domain.favorites.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@Schema(description = "관심종목 응답 정보")
public class FavoriteResponse {

    @Schema(description = "회원 ID", example = "123")
    Long memberId;

    @Schema(description = "주식명", example = "삼성전자")
    String stockName;

    @Schema(description = "주식 코드", example = "005930", pattern = "\\d{6}")
    String stockCode;
}
