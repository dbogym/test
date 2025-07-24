package io.gaboja9.mockstock.domain.notifications.service;

import io.gaboja9.mockstock.domain.mails.entity.Mails;
import io.gaboja9.mockstock.domain.mails.repository.MailsRepository;
import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.domain.members.repository.MembersRepository;
import io.gaboja9.mockstock.domain.notifications.entity.Notifications;
import io.gaboja9.mockstock.domain.notifications.enums.NotificationType;
import io.gaboja9.mockstock.domain.notifications.repository.NotificationsRepository;
import io.gaboja9.mockstock.domain.trades.entity.TradeType;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.stereotype.Service;

import java.text.NumberFormat;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationsService {

    private final NotificationsRepository notificationsRepository;
    private final MembersRepository membersRepository;
    private final MailsRepository mailsRepository;

    // 매매 알림
    // 1. 매매 완료시 메일 발송
    public void sendTradeNotification(
            Long memberId,
            String stockCode,
            String stockName,
            TradeType tradeType,
            int quantity,
            int price) {

        if (!tradeNotificationEnabled(memberId)) {
            log.debug("사용자 {}의 매매 알림이 비활성화되어 있습니다.", memberId);
            return;
        }

        Optional<Members> member = membersRepository.findById(memberId);

        String subject = createTradeSubject(stockName, tradeType, quantity, price);
        String content = createTradeContent(stockCode, stockName, tradeType, quantity, price);

        Mails mail = new Mails(subject, content, true, null, member.get());
        mailsRepository.save(mail);

        log.info("매매 알림 발송 완료 - 사용자: {}, 종목: {}, 타입: {}", memberId, stockName, tradeType.name());
    }

    // 2. 사용자의 매매 알림 설정 확인
    private boolean tradeNotificationEnabled(Long memberId) {
        return notificationsRepository
                .findByMembersId(memberId)
                .map(Notifications::isTradeNotificationEnabled)
                .orElse(true);
    }

    // 3. 매매 알림 제목 생성
    private String createTradeSubject(
            String stockName, TradeType tradeType, int quantity, int price) {

        String action = tradeType == TradeType.BUY ? "매수" : "매도";
        String formattedPrice = NumberFormat.getNumberInstance(Locale.KOREA).format(price);

        return String.format(
                "%s %s %d주 %s 완료 (%s원)",
                NotificationType.TRADE.getPrefix(), stockName, quantity, action, formattedPrice);
    }

    // 4. 매매 알림 내용 생성
    private String createTradeContent(
            String stockCode, String stockName, TradeType tradeType, int quantity, int price) {
        String action = tradeType == TradeType.BUY ? "매수" : "매도";
        String formattedPrice = NumberFormat.getNumberInstance(Locale.KOREA).format(price);
        String totalAmount = NumberFormat.getNumberInstance(Locale.KOREA).format(quantity * price);

        StringBuilder content = new StringBuilder();
        content.append(String.format("%s가 완료되었습니다.\n\n", action));
        content.append(String.format("종목명: %s (%s) \n", stockName, stockCode));
        content.append(String.format("거래수량: %d주 \n", quantity));
        content.append(String.format("체결가격: %s원 \n", formattedPrice));
        content.append(String.format("총 거래금액: %s원 \n\n", totalAmount));
        content.append("※ 거래 내역 및 알림 설정은 마이페이지에서 확인하실 수 있습니다.");

        return content.toString();
    }

    // 시장 시간 알림
    // 1. 시장 개장 알림
    public void sendMarketOpenNotification() {
        List<Members> targetMembers = getMarketNotificationEnabledMembers();

        if (targetMembers.isEmpty()) {
            log.info("시장 개장 알림을 받을 사용자가 없습니다.");
            return;
        }

        String subject = createMarketOpenSubject();
        String content = createMarketOpenContent();

        int sentCount = 0;
        for (Members member : targetMembers) {
            try {
                Mails mail = new Mails(subject, content, true, null, member);
                mailsRepository.save(mail);
                sentCount++;
            } catch (Exception e) {
                log.error("시장 개장 알림 발송 실패 - 사용자: {}", member.getId(), e);
            }
        }

        log.info("시장 개장 알림 발송 완료 - 총 {}명", sentCount);
    }

    // 2. 시장 마감 알림
    public void sendMarketCloseNotification() {
        List<Members> targetMembers = getMarketNotificationEnabledMembers();

        if (targetMembers.isEmpty()) {
            log.info("시장 마감 알림을 받을 사용자가 없습니다.");
            return;
        }

        String subject = createMarketCloseSubject();
        String content = createMarketCloseContent();

        int sentCount = 0;
        for (Members member : targetMembers) {
            try {
                Mails mail = new Mails(subject, content, true, null, member);
                mailsRepository.save(mail);
                sentCount++;
            } catch (Exception e) {
                log.error("시장 마감 알림 발송 실패 - 사용자: {}", member.getId(), e);
            }
        }

        log.info("시장 마감 알림 발송 완료 - 총 {}명", sentCount);
    }

    // 3. 시장 시간 알림이 활성화된 회원 조회
    private List<Members> getMarketNotificationEnabledMembers() {
        return membersRepository.findAll().stream()
                .filter(member -> marketNotificationEnabled(member.getId()))
                .toList();
    }

    // 사용자의 시장 시간 알림 설정 확인
    private boolean marketNotificationEnabled(Long memberId) {
        return notificationsRepository
                .findByMembersId(memberId)
                .map(Notifications::isMarketNotificationEnabled)
                .orElse(true);
    }

    // 4. 시장 시작 알림 제목 생성
    private String createMarketOpenSubject() {
        String today = LocalDate.now().format(DateTimeFormatter.ofPattern("M월 d일"));

        return String.format(
                "%s %s 주식시장이 10분 후 개장합니다.", NotificationType.MARKET_TIME.getPrefix(), today);
    }

    // 5. 시장 시작 알림 내용 생성
    private String createMarketOpenContent() {
        String today = LocalDate.now().format(DateTimeFormatter.ofPattern("M월 d일"));

        StringBuilder content = new StringBuilder();

        content.append(String.format("%s 한국 주식시장 개장 안내 \n\n", today));
        content.append("📈 오늘의 거래가 곧 시작됩니다! \n\n");
        content.append("⏰ 개장 시간: 오전 9:00 \n");
        content.append("⏰ 마감 시간: 오후 3:30 \n\n");
        content.append("오늘도 성공적인 투자 되세요! \n\n");
        content.append("※ 알림 설정은 마이페이지에서 변경하실 수 있습니다.");

        return content.toString();
    }

    // 6. 시장 마감 알림 제목 생성
    private String createMarketCloseSubject() {
        String today = LocalDate.now().format(DateTimeFormatter.ofPattern("M월 d일"));

        return String.format(
                "%s %s 주식시장이 10분 후 마감합니다.", NotificationType.MARKET_TIME.getPrefix(), today);
    }

    // 7. 시장 마감 알림 내용 생성
    private String createMarketCloseContent() {
        String today = LocalDate.now().format(DateTimeFormatter.ofPattern("M월 d일"));

        StringBuilder content = new StringBuilder();

        content.append(String.format("%s 한국 주식시장 마감 안내 \n\n", today));
        content.append("📈 오늘의 거래가 곧 마감됩니다! \n\n");
        content.append("⏰ 마감까지 약 10분 남았습니다. \n");
        content.append("⏰ 마감 시간: 오후 3:30 \n\n");
        content.append("마지막 거래 기회를 놓치지 마세요! \n\n");
        content.append("내일도 좋은 하루 되세요! \n\n");
        content.append("※ 알림 설정은 마이페이지에서 변경하실 수 있습니다.");

        return content.toString();
    }
}
