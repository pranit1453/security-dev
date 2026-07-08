package com.pranit.security.authentication.jwt.helper;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class KeyService {
    private KeyService() {
    }

    public static PrivateKey loadPrivateKey(final String pemPath) {
        try {
            final String key = readKeyFromResource(pemPath)
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            final byte[] decoded = Base64.getDecoder().decode(key);
            final PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Failed to load private key: " + pemPath, e);
        }
    }


    private static String readKeyFromResource(final String pemPath) throws IOException {
        try (final InputStream is = KeyService.class.getClassLoader().getResourceAsStream(pemPath)) {
            if (is == null) {
                throw new RuntimeException("Resource not found: " + pemPath);
            }
            return new String(is.readAllBytes());
        }
    }

    public static PublicKey loadPublicKey(final String pemPath) {
        try {
            final String Key = readKeyFromResource(pemPath)
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            final byte[] decoded = Base64.getDecoder().decode(Key);
            final X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Failed to load public key: " + pemPath, e);
        }
    }
}
