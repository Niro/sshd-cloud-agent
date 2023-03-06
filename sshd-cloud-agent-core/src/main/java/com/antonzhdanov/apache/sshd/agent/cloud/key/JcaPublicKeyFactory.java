package com.antonzhdanov.apache.sshd.agent.cloud.key;

import lombok.SneakyThrows;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.util.io.der.ASN1Object;
import org.apache.sshd.common.util.io.der.ASN1Type;
import org.apache.sshd.common.util.io.der.DERParser;

import java.io.BufferedReader;
import java.io.StreamCorruptedException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;

public class JcaPublicKeyFactory implements PublicKeyFactory {

    private static final String RSA = "RSA";
    private static final String EC = "EC";

    private static final String RSA_OID = "1.2.840.113549.1.1.1";
    private static final String EC_OID = "1.2.840.10045.2.1";

    @Override
    public PublicKey create(String pem) {
        BufferedReader bufferedReader = new BufferedReader(new StringReader(pem));
        String encoded = bufferedReader.lines()
                .filter(line -> !line.startsWith("-----BEGIN") && !line.startsWith("-----END"))
                .collect(Collectors.joining());

        return create(Base64.getDecoder().decode(encoded));
    }

    @Override
    public PublicKey create(byte[] encoded) {
        String algorithm = determineAlgorithm(encoded);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);

        return create(keySpec, algorithm);
    }

    @Override
    public RSAPublicKey create(BigInteger modulus, BigInteger publicExponent) {
        return (RSAPublicKey) create(new RSAPublicKeySpec(modulus, publicExponent), RSA);
    }

    @Override
    public ECPublicKey create(BigInteger x, BigInteger y, ECCurves ecCurve) {
        return (ECPublicKey) create(new ECPublicKeySpec(new ECPoint(x, y), ecCurve.getParameters()), EC);
    }

    @SneakyThrows
    private PublicKey create(KeySpec keySpec, String algorithm) {
        return KeyFactory.getInstance(algorithm).generatePublic(keySpec);
    }

    private String determineAlgorithm(byte[] bytes) {
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
                return RSA;
            case EC_OID:
                return EC;
            default:
                throw new UnsupportedOperationException("Unknown algorithm for OID " + oid);
        }
    }
}
