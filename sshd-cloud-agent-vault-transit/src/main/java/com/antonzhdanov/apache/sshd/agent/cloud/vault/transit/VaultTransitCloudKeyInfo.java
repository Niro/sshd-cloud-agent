package com.antonzhdanov.apache.sshd.agent.cloud.vault.transit;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudProvider;

import static java.util.Objects.requireNonNull;

public class VaultTransitCloudKeyInfo implements CloudKeyInfo {

    private final String keyId;

    public VaultTransitCloudKeyInfo(String keyId) {
        this.keyId = requireNonNull(keyId, "keyId");
    }

    public String getKeyId() {
        return keyId;
    }

    @Override
    public String getComment() {
        return "Vault Transit " + keyId;
    }

    @Override
    public CloudProvider getCloudProvider() {
        return VaultTransitCloudProvider.INSTANCE;
    }

    @Override
    public String toString() {
        return getComment();
    }
}
