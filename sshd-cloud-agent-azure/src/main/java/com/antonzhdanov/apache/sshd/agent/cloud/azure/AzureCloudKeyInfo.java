package com.antonzhdanov.apache.sshd.agent.cloud.azure;

import com.antonzhdanov.apache.sshd.agent.cloud.AbstractCloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudProvider;

public class AzureCloudKeyInfo extends AbstractCloudKeyInfo {

    public AzureCloudKeyInfo(String keyId) {
        super(keyId);
    }

    @Override
    public String getComment() {
        return "Azure " + getKeyId();
    }

    @Override
    public CloudProvider getCloudProvider() {
        return AzureCloudProvider.INSTANCE;
    }
}
