package com.antonzhdanov.apache.sshd.agent.cloud.azure;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudProvider;
import lombok.Builder;
import lombok.Data;

import static java.util.Objects.requireNonNull;

@Data
@Builder
public class AzureCloudKeyInfo implements CloudKeyInfo {
    private final String keyId;

    public AzureCloudKeyInfo(String keyId) {
        this.keyId = requireNonNull(keyId, "keyId");
    }

    @Override
    public String getComment() {
        return "Azure " + keyId;
    }

    @Override
    public CloudProvider getCloudProvider() {
        return AzureCloudProvider.INSTANCE;
    }
}
