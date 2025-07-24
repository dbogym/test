package io.gaboja9.mockstock.domain.notifications.entity;

import io.gaboja9.mockstock.domain.members.entity.Members;
import io.gaboja9.mockstock.global.common.BaseEntity;

import jakarta.persistence.*;

import lombok.*;

@Getter
@Entity
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class Notifications extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Setter @Builder.Default private boolean tradeNotificationEnabled = true;

    @Setter @Builder.Default private boolean marketNotificationEnabled = true;

    @Setter @Builder.Default private int marketOpenNotificationMinute = 10;

    @Setter @Builder.Default private int marketCloseNotificationMinute = 10;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "members_id", unique = true)
    private Members members;
}
