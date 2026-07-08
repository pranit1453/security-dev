package com.pranit.security.authentication.jwt.helper;

import com.pranit.security.authentication.jwt.constants.Claim;
import com.pranit.security.authentication.jwt.service.ExtractClaim;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.util.UUID;

@Slf4j
@Service
public final class ExtractClaimImpl implements ExtractClaim {
    private final PublicKey publicKey;

    public ExtractClaimImpl() {
        this.publicKey = KeyService.loadPublicKey("keys/public_key.pem");
    }

    @Override
    public String getUsernameFromAccessToken(final Claims claims) {
        return claims.getSubject();
    }

    @Override
    public String getUsernameFromRefreshToken(final Claims claims) {
        return claims.getSubject();
    }

    @Override
    public UUID getUserIdFromAccessToken(final Claims claims) {
        final String userId = claims.getId();
        return UUID.fromString(userId);
    }

    @Override
    public String getJtiFromRefreshToken(final Claims claims) {
        return claims.getId();
    }

    @Override
    public Claims validateAndParseToken(final String token) {
        try {
            return Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (MalformedJwtException | ExpiredJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
            log.error("JWT validation failed: {}", ex.getMessage());
            throw new JwtException("Invalid or expired JWT", ex);
        }
    }

    @Override
    public boolean isRefreshToken(final Claims claims) {
        return Claim.REFRESH.equals(claims.get(Claim.TOKEN_TYPE, String.class));
    }

    @Override
    public boolean isAccessToken(final Claims claims) {
        return Claim.ACCESS.equals(claims.get(Claim.TOKEN_TYPE, String.class));
    }

    @Override
    public String getSessionIdFromAccessToken(Claims claims) {
        return claims.get(Claim.SESSIONID, String.class);
    }

}
