package com.antonzhdanov.apache.sshd.agent.cloud;

import java.security.PublicKey;

import static java.util.Objects.requireNonNull;

public abstract class CloudPublicKey<K extends CloudKeyInfo, T extends PublicKey> implements PublicKey {
    private final T publicKey;
    private final K cloudKeyInfo;

    protected CloudPublicKey(T publicKey, K cloudKeyInfo) {
        this.publicKey = requireNonNull(publicKey, "publicKey");
        this.cloudKeyInfo = requireNonNull(cloudKeyInfo, "cloudKeyInfo");
    }

    @Override
    public String getAlgorithm() {
        return publicKey.getAlgorithm();
    }

    @Override
    public String getFormat() {
        return publicKey.getFormat();
    }

    @Override
    public byte[] getEncoded() {
        return publicKey.getEncoded();
    }

    protected T getPublicKey() {
        return publicKey;
    }

    public K getCloudKeyInfo() {
        return cloudKeyInfo;
    }
}
