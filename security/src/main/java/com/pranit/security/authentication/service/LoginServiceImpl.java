package com.pranit.security.authentication.service;

import com.pranit.security.authentication.dto.SigninRequest;
import com.pranit.security.authentication.dto.SigninResponse;
import com.pranit.security.authentication.entity.RefreshToken;
import com.pranit.security.authentication.entity.UserDetail;
import com.pranit.security.authentication.exception.AccountDeleted;
import com.pranit.security.authentication.jwt.service.CookieService;
import com.pranit.security.authentication.jwt.service.GenerateToken;
import com.pranit.security.authentication.repository.RefreshTokenRepository;
import com.pranit.security.shared.exception.Unauthorized;
import com.pranit.security.shared.helper.Generate;
import com.pranit.security.shared.properties.TokenProperties;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class LoginServiceImpl implements LoginService {

    private final AuthenticationManager authenticationManager;
    private final TokenProperties tokenProperties;
    private final RefreshTokenRepository refreshTokenRepository;
    private final CookieService cookieService;
    private final GenerateToken generateToken;

    @Override
    @Transactional
    public SigninResponse authenticateUser(SigninRequest request, HttpServletResponse response) {
        log.debug("Authentication attempt initiated for username: {}", request.username());
        final Authentication authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(
                        request.username(),
                        request.password()));
        final Object principal = authentication.getPrincipal();
        if (!(principal instanceof UserDetail user)) {
            log.warn("Invalid authentication principal returned for username: {}", request.username());
            throw new Unauthorized("Invalid authentication principal");
        }
        if (user.isDeleted()) {
            log.warn("Deleted account login attempt for userId={}", user.getUserId());
            throw new AccountDeleted("Account has been deleted");
        }
        final String jti = Generate.generateJti();
        final Instant now = Instant.now();

        final RefreshToken refreshTokenEntity = RefreshToken.builder()
                .jti(jti)
                .userDetail(user)
                .expiresAt(now.plusSeconds(tokenProperties.refreshToken().expiration()))
                .revoked(false)
                .build();
        refreshTokenRepository.save(refreshTokenEntity);
        log.debug("Refresh token persisted successfully for userId: {}", user.getUserId());
        final String sessionId = Generate.generateSessionId();
        final String accessToken = generateToken.generateAccessToken(user, sessionId);
        final String refreshToken = generateToken.generateRefreshToken(user, jti, sessionId);
        log.info("User authenticated successfully for userId: {}", user.getUserId());

        cookieService.attachAccessTokenCookie(response, accessToken, Duration.ofMinutes(tokenProperties.accessToken().expiration()));
        cookieService.attachRefreshTokenCookie(response, refreshToken, Duration.ofMinutes(tokenProperties.refreshToken().expiration()));
        cookieService.addNoStoreHeaders(response);

        return SigninResponse.builder()
                .username(user.getUsername())
                .roles(extractRoles(user))
                .permissions(extractPermissions(user))
                .build();
    }

    private Set<String> extractRoles(final UserDetail user) {
        return user.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .filter(Objects::nonNull)
                .filter(role -> role.startsWith("ROLE_"))
                .collect(Collectors.toSet());
    }

    private Set<String> extractPermissions(final UserDetail user) {
        return user.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .filter(Objects::nonNull)
                .filter(permission -> !permission.startsWith("ROLE_"))
                .collect(Collectors.toSet());
    }
}
