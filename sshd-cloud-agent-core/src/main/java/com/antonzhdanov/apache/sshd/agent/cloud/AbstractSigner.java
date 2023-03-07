package com.antonzhdanov.apache.sshd.agent.cloud;

import com.antonzhdanov.apache.sshd.agent.cloud.key.CloudPublicKey;

import java.security.PublicKey;

import static java.util.Objects.requireNonNull;

public abstract class AbstractSigner<K extends CloudKeyInfo> implements Signer<K> {

    private final Class<K> keyInfoType;

    protected AbstractSigner(Class<K> keyInfoType) {
        this.keyInfoType = requireNonNull(keyInfoType, "keyInfoType");
    }

    @Override
    public boolean supports(PublicKey publicKey) {
        if (publicKey instanceof CloudPublicKey) {
            return ((CloudPublicKey<?, ?>) publicKey).getCloudKeyInfo().getClass() == keyInfoType;
        }

        return false;
    }
}
