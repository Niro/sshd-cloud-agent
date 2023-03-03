package com.antonzhdanov.apache.sshd.agent.cloud;

import java.io.BufferedReader;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;

public class PublicKeyUtils {
    private PublicKeyUtils() {
        throw new UnsupportedOperationException();
    }

    public static PublicKey parsePublicKey(byte[] encoded) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);

            return KeyFactory.getInstance("RSA").generatePublic(keySpec);
        } catch (Exception exc) {
            throw new RuntimeException("Unable to generate public key", exc);
        }
    }

    public static PublicKey fromPem(String pem) {
        BufferedReader bufferedReader = new BufferedReader(new StringReader(pem));
        String encoded = bufferedReader.lines()
                .filter(line -> !line.startsWith("-----BEGIN") && !line.startsWith("-----END"))
                .collect(Collectors.joining());

        return parsePublicKey(Base64.getDecoder().decode(encoded));
    }
}
