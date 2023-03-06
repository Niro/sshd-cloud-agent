package com.antonzhdanov.apache.sshd.agent.cloud.key;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.key.EcCloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.key.PublicKeyFactory;
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
import java.util.Objects;

@SuppressWarnings("unchecked")
public class CloudPublicKeyFactory<K extends CloudKeyInfo> {

    private final PublicKeyFactory publicKeyFactory;

    public CloudPublicKeyFactory(PublicKeyFactory publicKeyFactory) {
        this.publicKeyFactory = Objects.requireNonNull(publicKeyFactory, "publicKeyFactory");
    }

    public CloudPublicKey<K, PublicKey> create(String pem, K cloudKeyInfo) {
        return (CloudPublicKey<K, PublicKey>) create(publicKeyFactory.create(pem), cloudKeyInfo);
    }

    public CloudPublicKey<K, PublicKey> create(byte[] encoded, K cloudKeyInfo) {
        return (CloudPublicKey<K, PublicKey>) create(publicKeyFactory.create(encoded), cloudKeyInfo);
    }

    public CloudPublicKey<K, PublicKey> create(BigInteger modulus, BigInteger publicExponent, K cloudKeyInfo) {
        return (CloudPublicKey<K, PublicKey>) create(publicKeyFactory.create(modulus, publicExponent), cloudKeyInfo);
    }

    public CloudPublicKey<K, PublicKey> create(BigInteger x, BigInteger y, ECCurves ecCurve, K cloudKeyInfo) {
        return (CloudPublicKey<K, PublicKey>) create(publicKeyFactory.create(x, y, ecCurve), cloudKeyInfo);
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
}
