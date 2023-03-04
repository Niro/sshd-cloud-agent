package com.antonzhdanov.apache.sshd.agent.cloud;

import org.apache.sshd.common.util.io.der.ASN1Object;
import org.apache.sshd.common.util.io.der.ASN1Type;
import org.apache.sshd.common.util.io.der.DERParser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StreamCorruptedException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import static org.apache.sshd.common.config.keys.loader.pem.ECDSAPEMResourceKeyPairParser.ECDSA_OID;
import static org.apache.sshd.common.config.keys.loader.pem.RSAPEMResourceKeyPairParser.RSA_OID;

public class PublicKeyUtils {
    private PublicKeyUtils() {
        throw new UnsupportedOperationException();
    }

    public static PublicKey parsePublicKey(byte[] encoded) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);

            String algorithm = determineAlgorithm(encoded);
            return KeyFactory.getInstance(algorithm).generatePublic(keySpec);
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

    private static String determineAlgorithm(byte[] bytes) {
        String oid;
        try (DERParser parser = new DERParser(bytes)) {
            ASN1Object publicKeyInfo = parser.readObject();

            if (publicKeyInfo.getObjType() != ASN1Type.SEQUENCE) {
                throw new StreamCorruptedException("Not a top level sequence");
            }

            try (DERParser publicKetInfoParser = publicKeyInfo.createParser()) {
                ASN1Object version = publicKetInfoParser.readObject();

                if (version.getObjType() != ASN1Type.SEQUENCE) {
                    throw new StreamCorruptedException("No version");
                }

                try (DERParser versionParser = version.createParser()) {
                    oid = versionParser.readObject()
                            .asOID()
                            .stream()
                            .map(Object::toString)
                            .collect(Collectors.joining("."));
                }
            }
        } catch (Exception exc) {
            throw new RuntimeException(exc.getMessage());
        }

        switch (oid) {
            case RSA_OID:
                return "RSA";
            case ECDSA_OID:
                throw new UnsupportedOperationException("ECDSA is not supported yet, use RSA");
            default:
                throw new UnsupportedOperationException("Unknown algorithm for OID " + oid);
        }
    }
}
