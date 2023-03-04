package com.antonzhdanov.apache.sshd.agent.cloud;

import com.antonzhdanov.apache.sshd.agent.cloud.key.EcCloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.key.RsaCloudPublicKey;
import org.apache.sshd.common.util.io.der.ASN1Object;

import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

public class CloudPublicKeyFactory {
    public <K extends CloudKeyInfo> CloudPublicKey<K, ? extends PublicKey> create(PublicKey publicKey, K cloudKeyInfo) {
        if (publicKey instanceof RSAPublicKey) {
            return new RsaCloudPublicKey<>((RSAPublicKey) publicKey, cloudKeyInfo);
        } if (publicKey instanceof ECPublicKey) {
            return new EcCloudPublicKey<>((ECPublicKey) publicKey, cloudKeyInfo);
        } else {
            throw new UnsupportedOperationException("Unsupported key");
        }
    }
}
