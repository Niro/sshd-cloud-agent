package com.antonzhdanov.apache.sshd.agent.cloud.key;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

public class EcCloudPublicKey<K extends CloudKeyInfo> extends CloudPublicKey<K, ECPublicKey> implements ECPublicKey {
    public EcCloudPublicKey(ECPublicKey ecPublicKey, K keyInfo) {
        super(ecPublicKey, keyInfo);
    }

    @Override
    public ECPoint getW() {
        return getPublicKey().getW();
    }

    @Override
    public ECParameterSpec getParams() {
        return getPublicKey().getParams();
    }
}
