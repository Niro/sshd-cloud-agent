package com.antonzhdanov.apache.sshd.agent.cloud.key;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKey;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;

public class DsaCloudPublicKey<K extends CloudKeyInfo> extends CloudPublicKey<K, DSAPublicKey> implements DSAPublicKey {

    public DsaCloudPublicKey(DSAPublicKey publicKey, K keyInfo) {
        super(publicKey, keyInfo);
    }

    @Override
    public BigInteger getY() {
        return getPublicKey().getY();
    }

    @Override
    public DSAParams getParams() {
        return getPublicKey().getParams();
    }
}
