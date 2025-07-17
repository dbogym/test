package io.gaboja9.mockstock.domain.members.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import io.gaboja9.mockstock.domain.members.dto.request.MemosCreateRequestDto;
import io.gaboja9.mockstock.domain.members.dto.response.MemberInfoDto;
import io.gaboja9.mockstock.domain.members.dto.response.MemoResponseDto;
import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.members.exception.NotFoundMemberException;
import io.gaboja9.mockstock.domain.members.repository.MembersRepository;
import io.gaboja9.mockstock.domain.portfolios.dto.response.PortfoliosResponseDto;
import io.gaboja9.mockstock.domain.portfolios.service.PortfoliosService;
import io.gaboja9.mockstock.domain.ranks.service.RanksService;
import io.gaboja9.mockstock.domain.trades.repository.TradesRepository;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;

@ExtendWith(MockitoExtension.class)
class MembersServiceTest {

    @InjectMocks private MembersService membersService;

    @Mock private MembersRepository membersRepository;

    @Mock private TradesRepository tradesRepository;

    @Mock private RanksService ranksService;

    @Mock private PortfoliosService portfoliosService;

    @Test
    void getMemberInfoDto_정상() {
        // given
        Long memberId = 1L;

        Members member =
                new Members(
                        memberId,
                        "test@example.com",
                        "testUser",
                        "google",
                        "test.png",
                        5000,
                        0,
                        LocalDateTime.now().minusDays(15));

        PortfoliosResponseDto portfolios =
                PortfoliosResponseDto.builder()
                        .totalProfit(10000)
                        .totalEvaluationAmount(50000)
                        .cashBalance(20000)
                        .portfolios(null)
                        .build();

        given(membersRepository.findById(memberId)).willReturn(Optional.of(member));
        given(tradesRepository.countByMembersId(memberId)).willReturn(5);

        // when
        MemberInfoDto result = membersService.getMemberInfoDto(memberId, portfolios);

        // then
        assertThat(result.getNickname()).isEqualTo("testUser");
        assertThat(result.getProfileImage()).isEqualTo("test.png");
        assertThat(result.getTotalProfit()).isEqualTo(10000);
        assertThat(result.getTotalEvaluationAmount()).isEqualTo(50000);
        assertThat(result.getTradeCnt()).isEqualTo(5);
        assertThat(result.getPeriod()).isEqualTo(15);
        assertThat(result.getBankruptcyCnt()).isEqualTo(0);
    }

    @Test
    void getMemberInfoDto_유저없음_예외발생() {
        // given
        Long memberId = 999L;
        PortfoliosResponseDto dummyPortfolios =
                PortfoliosResponseDto.builder()
                        .totalProfit(0)
                        .totalEvaluationAmount(0)
                        .cashBalance(0)
                        .portfolios(null)
                        .build();

        given(membersRepository.findById(memberId)).willReturn(Optional.empty());

        // when & then
        assertThrows(
                NotFoundMemberException.class,
                () -> membersService.getMemberInfoDto(memberId, dummyPortfolios));
    }

    @Test
    void processBankruptcy_정상작동() {
        // given
        Long memberId = 1L;

        Members member =
                new Members(
                        memberId,
                        "test@example.com",
                        "nickname",
                        "google",
                        "profile.png",
                        50_000_000,
                        2,
                        LocalDateTime.now().minusDays(30));

        given(membersRepository.findById(memberId)).willReturn(Optional.of(member));

        // when
        membersService.processBankruptcy(memberId);

        // then
        verify(membersRepository).findById(memberId);
        verify(portfoliosService).remove(memberId);
        assertThat(member.getCashBalance()).isEqualTo(30_000_000);
        assertThat(member.getBankruptcyCnt()).isEqualTo(3);
    }

    @Test
    void processBankruptcy_없는회원_예외발생() {
        // given
        Long memberId = 999L;
        given(membersRepository.findById(memberId)).willReturn(Optional.empty());

        // when & then
        assertThrows(
                NotFoundMemberException.class, () -> membersService.processBankruptcy(memberId));
        verify(portfoliosService, never()).remove(any());
    }

    @Test
    public void createMemo_정상() {
        // given
        Long memberId = 1L;

        Members member =
                new Members(
                        memberId,
                        "test@example.com",
                        "testUser",
                        "google",
                        "test.png",
                        5000,
                        0,
                        LocalDateTime.now());

        MemosCreateRequestDto dto = MemosCreateRequestDto.builder().memo("테스트 메모").build();

        given(membersRepository.findById(memberId)).willReturn(Optional.of(member));

        // when
        membersService.createMemo(memberId, dto);

        // then
        assertThat(member.getMemo()).isEqualTo("테스트 메모");
        then(membersRepository).should().findById(memberId);
    }

    @Test
    public void createMemo_유저없음예외() {
        // given
        Long memberId = 1L;
        MemosCreateRequestDto dto = MemosCreateRequestDto.builder().memo("테스트 메모").build();
        given(membersRepository.findById(memberId)).willReturn(Optional.empty());

        // when & then
        assertThatThrownBy(() -> membersService.createMemo(memberId, dto))
                .isInstanceOf(NotFoundMemberException.class)
                .hasMessageContaining(memberId.toString());
    }

    @Test
    public void getMemo_정상() {
        // given
        Long memberId = 1L;

        Members member =
                new Members(
                        memberId,
                        "test@example.com",
                        "testUser",
                        "google",
                        "test.png",
                        5000,
                        0,
                        LocalDateTime.now());

        MemosCreateRequestDto dto = MemosCreateRequestDto.builder().memo("테스트 메모").build();

        given(membersRepository.findById(memberId)).willReturn(Optional.of(member));

        // when
        membersService.createMemo(memberId, dto);
        MemoResponseDto responseDto = membersService.getMemo(memberId);

        // then
        assertThat(dto.getMemo()).isEqualTo(responseDto.getMemo());
        then(membersRepository).should(times(2)).findById(memberId);
    }
}
