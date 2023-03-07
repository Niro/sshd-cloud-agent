package com.antonzhdanov.apache.sshd.agent.cloud.azure;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudProvider;

public class AzureCloudProvider implements CloudProvider {

    public static final AzureCloudProvider INSTANCE = new AzureCloudProvider();

    private AzureCloudProvider() {

    }

    @Override
    public String getName() {
        return "Azure";
    }
}
