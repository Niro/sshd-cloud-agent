package com.antonzhdanov.apache.sshd.agent.cloud.key;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

public class RsaCloudPublicKey<K extends CloudKeyInfo> extends CloudPublicKey<K, RSAPublicKey> implements RSAPublicKey {

    public RsaCloudPublicKey(RSAPublicKey publicKey, K cloudKeyInfo) {
        super(publicKey, cloudKeyInfo);
    }

    @Override
    public BigInteger getPublicExponent() {
        return getPublicKey().getPublicExponent();
    }

    @Override
    public BigInteger getModulus() {
        return getPublicKey().getModulus();
    }
}
