package io.gaboja9.mockstock.domain.members.controller;

import io.gaboja9.mockstock.domain.auth.dto.MembersDetails;
import io.gaboja9.mockstock.domain.mails.dto.response.MailsResponseDto;
import io.gaboja9.mockstock.domain.mails.service.MailsService;
import io.gaboja9.mockstock.domain.members.dto.request.MemosCreateRequestDto;
import io.gaboja9.mockstock.domain.members.dto.response.MemberInfoDto;
import io.gaboja9.mockstock.domain.members.dto.response.MemoResponseDto;
import io.gaboja9.mockstock.domain.members.service.MembersService;
import io.gaboja9.mockstock.domain.portfolios.dto.response.PortfoliosResponseDto;
import io.gaboja9.mockstock.domain.portfolios.service.PortfoliosService;
import io.gaboja9.mockstock.domain.trades.dto.request.TradesRequestDto;
import io.gaboja9.mockstock.domain.trades.dto.response.TradesResponseDto;
import io.gaboja9.mockstock.domain.trades.service.TradesService;
import io.gaboja9.mockstock.global.exception.BaseException;
import io.gaboja9.mockstock.global.exception.ErrorCode;

import jakarta.validation.Valid;

import lombok.RequiredArgsConstructor;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/members/me")
@RequiredArgsConstructor
public class MembersController implements MembersControllerSpec {

    private final PortfoliosService portfoliosService;
    private final MembersService membersService;
    private final TradesService tradesService;
    private final MailsService mailsService;

    @GetMapping("/info")
    public ResponseEntity<MemberInfoDto> getMemberInfo(
            @AuthenticationPrincipal MembersDetails membersDetails) {

        Long currentId = membersDetails.getId();

        PortfoliosResponseDto portfolios = portfoliosService.getPortfolios(currentId);

        MemberInfoDto memberInfoDto = membersService.getMemberInfoDto(currentId, portfolios);

        return ResponseEntity.ok(memberInfoDto);
    }

    @GetMapping("/portfolios")
    public ResponseEntity<PortfoliosResponseDto> getPortfolios(
            @AuthenticationPrincipal MembersDetails membersDetails) {

        Long currentId = membersDetails.getId();

        PortfoliosResponseDto portfolios = portfoliosService.getPortfolios(currentId);

        return ResponseEntity.ok(portfolios);
    }

    @GetMapping("/trades")
    public ResponseEntity<Page<TradesResponseDto>> getTrades(
            @AuthenticationPrincipal MembersDetails membersDetails,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        Long currentId = membersDetails.getId();
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        Page<TradesResponseDto> trades = tradesService.getTrades(currentId, pageable);

        return ResponseEntity.ok(trades);
    }

    @GetMapping("/trades/search")
    public ResponseEntity<Page<TradesResponseDto>> getTradesWithOption(
            @AuthenticationPrincipal MembersDetails membersDetails,
            @Valid TradesRequestDto dto,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        Long currentId = membersDetails.getId();

        if ((dto.getStockCode() == null || dto.getStockCode().isBlank())
                && (dto.getStockName() == null || dto.getStockName().isBlank())) {
            throw new BaseException(
                    ErrorCode.INVALID_INPUT_VALUE, "stockCode 또는 stockName 중 하나는 필수입니다.");
        }

        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        Page<TradesResponseDto> trades =
                tradesService.getTradesWithOption(currentId, dto, pageable);

        return ResponseEntity.ok(trades);
    }

    @PostMapping("/memos")
    public ResponseEntity<String> createMemos(
            @Valid @RequestBody MemosCreateRequestDto dto,
            @AuthenticationPrincipal MembersDetails membersDetails) {

        Long currentId = membersDetails.getId();

        membersService.createMemo(currentId, dto);

        return ResponseEntity.status(HttpStatus.CREATED).body("메모 저장 완료");
    }

    @GetMapping("/memos")
    public ResponseEntity<MemoResponseDto> getMemos(
            @AuthenticationPrincipal MembersDetails membersDetails) {

        Long currentId = membersDetails.getId();

        MemoResponseDto memo = membersService.getMemo(currentId);

        return ResponseEntity.ok(memo);
    }

    @GetMapping("/mails")
    public ResponseEntity<Page<MailsResponseDto>> getMails(
            @AuthenticationPrincipal MembersDetails membersDetails,
            @RequestParam(required = false) Boolean unread,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        Long currentId = membersDetails.getId();
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());

        if (unread == null) {
            Page<MailsResponseDto> allMails = mailsService.getAllMails(currentId, pageable);
            return ResponseEntity.ok(allMails);
        }

        Page<MailsResponseDto> mailsByStatus =
                mailsService.getMailsByUnreadStatus(currentId, unread, pageable);
        return ResponseEntity.ok(mailsByStatus);
    }

    @PostMapping("/bankruptcy")
    public ResponseEntity<Void> declareBankruptcy(
            @AuthenticationPrincipal MembersDetails membersDetails) {

        Long currentId = membersDetails.getId();

        membersService.processBankruptcy(currentId);
        return ResponseEntity.noContent().build();
    }
}
