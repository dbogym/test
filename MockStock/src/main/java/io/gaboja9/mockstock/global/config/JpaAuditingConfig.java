package io.gaboja9.mockstock.global.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@Configuration
@EnableJpaAuditing
@Profile("!test") // test 프로필이 아닐 때만 활성화
public class JpaAuditingConfig {}
