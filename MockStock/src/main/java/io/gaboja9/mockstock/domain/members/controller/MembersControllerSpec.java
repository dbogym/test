package io.gaboja9.mockstock.domain.members.controller;

import io.gaboja9.mockstock.domain.mails.dto.response.MailsResponseDto;
import io.gaboja9.mockstock.domain.members.dto.request.MemosCreateRequestDto;
import io.gaboja9.mockstock.domain.members.dto.response.MemberInfoDto;
import io.gaboja9.mockstock.domain.members.dto.response.MemoResponseDto;
import io.gaboja9.mockstock.domain.portfolios.dto.response.PortfoliosResponseDto;
import io.gaboja9.mockstock.domain.trades.dto.request.TradesRequestDto;
import io.gaboja9.mockstock.domain.trades.dto.response.TradesResponseDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Tag(name = "마이페이지 컨트롤러", description = "마이페이지 API입니다.")
@RequestMapping("/members/me")
public interface MembersControllerSpec {

    @Operation(
            summary = "나의 정보를 불러옵니다.",
            description = "총 수익률, 총 자산, 총 거래횟수, 랭킹, 활동 기간을 불러옵니다.",
            responses =
                    @ApiResponse(
                            responseCode = "200",
                            description = "성공적으로 내 정보를 불러왔습니다.",
                            content =
                                    @Content(
                                            mediaType = "application/json",
                                            schema =
                                                    @Schema(implementation = MemberInfoDto.class))))
    @GetMapping("/info")
    ResponseEntity<MemberInfoDto> getMemberInfo();

    @Operation(
            summary = "포트폴리오를 불러옵니다.",
            description = "보유중인 현금, 평가금액, 총 손익, 총 수익률과 주식별 포트폴리오를 불러옵니다.",
            responses =
                    @ApiResponse(
                            responseCode = "200",
                            description = "성공적으로 포트폴리오를 불러왔습니다.",
                            content =
                                    @Content(
                                            mediaType = "application/json",
                                            schema =
                                                    @Schema(
                                                            implementation =
                                                                    PortfoliosResponseDto.class))))
    @GetMapping("/portfolios")
    ResponseEntity<PortfoliosResponseDto> getPortfolios();

    @Operation(
            summary = "전체 거래내역을 불러옵니다.",
            description = "해당 유저의 모든 거래내역을 불러옵니다.",
            responses =
                    @ApiResponse(
                            responseCode = "200",
                            description = "성공적으로 전체 거래내역을 불러왔습니다.",
                            content =
                                    @Content(
                                            mediaType = "application/json",
                                            schema =
                                                    @Schema(
                                                            type = "array",
                                                            implementation =
                                                                    TradesResponseDto.class))))
    @GetMapping("/trades")
    ResponseEntity<Page<TradesResponseDto>> getTrades(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size);

    @Operation(
            summary = "조건별 거래내역을 불러옵니다.",
            description = "조건에 부합하는 거래내역을 불러옵니다.",
            responses =
                    @ApiResponse(
                            responseCode = "200",
                            description = "성공적으로 조건별 거래내역을 불러왔습니다.",
                            content =
                                    @Content(
                                            mediaType = "application/json",
                                            schema =
                                                    @Schema(
                                                            type = "array",
                                                            implementation =
                                                                    TradesResponseDto.class))))
    @GetMapping("/trades/search")
    ResponseEntity<Page<TradesResponseDto>> getTradesWithOption(
            @ModelAttribute TradesRequestDto dto,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size);

    @Operation(
            summary = "메모를 저장합니다.",
            description = "사용자는 투자전략 등의 메모를 저장합니다.",
            responses =
                    @ApiResponse(
                            responseCode = "201",
                            description = "성공적으로 메모가 저장되었습니다.",
                            content =
                                    @Content(
                                            mediaType = "application/json",
                                            schema = @Schema(implementation = String.class))))
    @PostMapping("/memos")
    ResponseEntity<String> createMemos(@RequestBody MemosCreateRequestDto dto);

    @Operation(
            summary = "메모를 불러옵니다.",
            description = "저장해둔 메모를 불러옵니다.",
            responses =
                    @ApiResponse(
                            responseCode = "200",
                            description = "성공적으로 메모를 불러왔습니다.",
                            content =
                                    @Content(
                                            mediaType = "application/json",
                                            schema =
                                                    @Schema(
                                                            implementation =
                                                                    MemoResponseDto.class))))
    @GetMapping("/memos")
    ResponseEntity<MemoResponseDto> getMemos();

    @Operation(
            summary = "메일을 불러옵니다.",
            description = "unread가 없으면 전체 메일, 있으면 unread의 상태에 따라 조건별 메일들을 불러옵니다.",
            responses =
                    @ApiResponse(
                            responseCode = "200",
                            description = "성공적으로 메일 목록을 불러왔습니다.",
                            content =
                                    @Content(
                                            mediaType = "application/json",
                                            schema =
                                                    @Schema(
                                                            type = "array",
                                                            implementation =
                                                                    MailsResponseDto.class))))
    @GetMapping("/mails")
    ResponseEntity<Page<MailsResponseDto>> getMails(
            @RequestParam(required = false) Boolean unread,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size);

    @Operation(
            summary = "파산 신청을 합니다.",
            description = "주식을 몰수하고 현금을 3천만 원으로 초기화합니다.",
            responses =
                    @ApiResponse(
                            responseCode = "204",
                            description = "성공적으로 파산 신청이 되었습니다.",
                            content = @Content(schema = @Schema(hidden = true))))
    @PostMapping("/bankruptcy")
    ResponseEntity<Void> declareBankruptcy();
}
