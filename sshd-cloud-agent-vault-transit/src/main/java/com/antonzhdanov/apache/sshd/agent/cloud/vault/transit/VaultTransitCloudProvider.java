package com.antonzhdanov.apache.sshd.agent.cloud.vault.transit;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudProvider;

public class VaultTransitCloudProvider implements CloudProvider {

    public static final VaultTransitCloudProvider INSTANCE = new VaultTransitCloudProvider();

    private VaultTransitCloudProvider() {

    }

    @Override
    public String getName() {
        return "Vault Transit";
    }
}
