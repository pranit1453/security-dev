package com.pranit.security.shared.helper;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

public final class Generate {

    private static final SecureRandom RANDOM = new SecureRandom();

    private Generate() {
    }

    public static String generateSessionId() {
        return UUID.randomUUID()
                .toString()
                .replace("-", "")
                .substring(0, 16);
    }

    public static String generateEventId() {
        return UUID.randomUUID().toString();
    }

    public static String generateJti() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

}
