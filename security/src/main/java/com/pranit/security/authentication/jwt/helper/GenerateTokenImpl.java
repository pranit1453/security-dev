package com.pranit.security.authentication.jwt.helper;

import com.pranit.security.authentication.entity.UserDetail;
import com.pranit.security.authentication.jwt.constants.Claim;
import com.pranit.security.authentication.jwt.service.GenerateToken;
import com.pranit.security.shared.properties.TokenProperties;
import com.pranit.security.shared.redis.RedisTokenStore;
import io.jsonwebtoken.Jwts;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;


@Slf4j
@Component
@Getter
public final class GenerateTokenImpl implements GenerateToken {

    private final TokenProperties properties;
    private final RedisTokenStore redisTokenStore;
    private final PrivateKey privateKey;

    public GenerateTokenImpl(TokenProperties properties, RedisTokenStore redisTokenStore) {
        this.properties = properties;
        this.redisTokenStore = redisTokenStore;
        this.privateKey = KeyService.loadPrivateKey("keys/private_key.pem");
    }

    @Override
    public String generateAccessToken(final UserDetail userDetail, final String sessionId) {
        final UUID userId = userDetail.getUserId();
        redisTokenStore.addTokenIdentifier(userId, sessionId);
        final String username = userDetail.getUsername();
        final Instant now = Instant.now();
        final Instant expiry = now.plusSeconds(properties.accessToken().expiration());
        final Set<String> roles = extractRoles(userDetail);
        return Jwts.builder()
                .id(userId.toString())
                .subject(username)
                .issuer(properties.token().issuer())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .claim(Claim.SESSIONID, sessionId)
                .claim(Claim.ROLES, roles)
                .claim(Claim.TOKEN_TYPE, Claim.ACCESS)
                .signWith(this.privateKey)
                .compact();
    }

    private Set<String> extractRoles(final UserDetail user) {
        return user.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .filter(Objects::nonNull)
                .filter(role -> role.startsWith("ROLE_"))
                .collect(Collectors.toSet());
    }

    @Override
    public String generateRefreshToken(final UserDetail userDetail, final String jti, final String sessionId) {
        final String username = userDetail.getUsername();
        final Instant now = Instant.now();
        final Instant expiry = now.plusSeconds(properties.refreshToken().expiration());
        return Jwts.builder()
                .id(jti)
                .subject(username)
                .issuer(properties.token().issuer())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .claim(Claim.SESSIONID, sessionId)
                .claim(Claim.TOKEN_TYPE, Claim.REFRESH)
                .signWith(this.privateKey)
                .compact();
    }

}
