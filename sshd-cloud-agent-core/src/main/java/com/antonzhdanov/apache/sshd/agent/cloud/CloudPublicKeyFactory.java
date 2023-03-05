package com.antonzhdanov.apache.sshd.agent.cloud;

import com.antonzhdanov.apache.sshd.agent.cloud.key.EcCloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.key.RsaCloudPublicKey;
import org.apache.sshd.common.cipher.ECCurves;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;

public class CloudPublicKeyFactory<K extends CloudKeyInfo> {

    public CloudPublicKey<K, ? extends PublicKey> create(String pem, K cloudKeyInfo) {
        return create(PublicKeyUtils.fromPem(pem), cloudKeyInfo);
    }

    public CloudPublicKey<K, ? extends PublicKey> create(BigInteger modulus,
                                                         BigInteger publicExponent,
                                                         K cloudKeyInfo) {
        KeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);

        return create(keySpec, "RSA", cloudKeyInfo);
    }

    public CloudPublicKey<K, ? extends PublicKey> create(BigInteger x,
                                                         BigInteger y,
                                                         ECCurves ecCurve,
                                                         K cloudKeyInfo) {
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(new ECPoint(x, y), ecCurve.getParameters());


        return create(ecPublicKeySpec, "EC", cloudKeyInfo);
    }

    public CloudPublicKey<K, ? extends PublicKey> create(PublicKey publicKey, K cloudKeyInfo) {
        if (publicKey instanceof RSAPublicKey) {
            return new RsaCloudPublicKey<>((RSAPublicKey) publicKey, cloudKeyInfo);
        } else if (publicKey instanceof ECPublicKey) {
            return new EcCloudPublicKey<>((ECPublicKey) publicKey, cloudKeyInfo);
        } else {
            throw new UnsupportedOperationException("Unsupported key");
        }
    }

    private CloudPublicKey<K, ? extends PublicKey> create(KeySpec keySpec,
                                                          String algorithm,
                                                          K cloudKeyInfo) {
        try {
            PublicKey publicKey = KeyFactory.getInstance(algorithm).generatePublic(keySpec);
            return create(publicKey, cloudKeyInfo);
        } catch (Exception exc) {
            // TODO
            throw new RuntimeException(exc);
        }
    }
}
