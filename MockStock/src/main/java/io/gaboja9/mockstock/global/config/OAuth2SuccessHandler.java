package io.gaboja9.mockstock.global.config;

import io.gaboja9.mockstock.domain.auth.dto.MembersDetails;
import io.gaboja9.mockstock.domain.auth.dto.TokenPair;
import io.gaboja9.mockstock.domain.auth.entity.RefreshToken;
import io.gaboja9.mockstock.domain.auth.service.AuthService;
import io.gaboja9.mockstock.domain.auth.service.JwtTokenProvider;
import io.gaboja9.mockstock.domain.members.entity.Members;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.HashMap;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Value("${custom.jwt.redirection.base}")
    private String baseUrl;

    private final AuthService authService;
    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

        MembersDetails principal = (MembersDetails) authentication.getPrincipal();

        log.info("principal = {}", principal);

        String email = principal.getEmail();
        log.info("email = {}", email);

        Members findMembers = authService.getById(principal.getId());

        HashMap<String, String> params = new HashMap<>();

        Optional<RefreshToken> refreshTokenOptional =
                jwtTokenProvider.findRefreshToken(principal.getId());

        if (refreshTokenOptional.isEmpty()) {
            TokenPair tokenPair = jwtTokenProvider.generateTokenPair(findMembers);
            params.put("access", tokenPair.getAccessToken());
            params.put("refresh", tokenPair.getRefreshToken());
        } else {
            String acceessToken =
                    jwtTokenProvider.issueAcceessToken(principal.getId(), principal.getRole());
            params.put("access", acceessToken);
            params.put("refresh", refreshTokenOptional.get().getRefreshToken());
        }

        String urlStr = genUrlString(params);

        log.info("urlStr = {}", urlStr);

        getRedirectStrategy().sendRedirect(request, response, urlStr);
    }

    private String genUrlString(HashMap<String, String> params) {
        return UriComponentsBuilder.fromUriString(baseUrl)
                .queryParam("access", params.get("access"))
                .queryParam("refresh", params.get("refresh"))
                .build()
                .toUri()
                .toString();
    }
}
