package io.gaboja9.mockstock.domain.notifications.enums;

public enum NotificationType {
    TRADE("[매매알림]"),
    MARKET_TIME("[시장알림]"),
    GENERAL("");

    private final String prefix;

    NotificationType(String prefix) {
        this.prefix = prefix;
    }

    public String getPrefix() {
        return prefix;
    }
}
