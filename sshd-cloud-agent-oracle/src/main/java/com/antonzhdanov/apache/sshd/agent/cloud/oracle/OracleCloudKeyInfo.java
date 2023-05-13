package com.antonzhdanov.apache.sshd.agent.cloud.oracle;

import com.antonzhdanov.apache.sshd.agent.cloud.AbstractCloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudProvider;

public class OracleCloudKeyInfo extends AbstractCloudKeyInfo {

    private final String keyVersionId;

    public OracleCloudKeyInfo(String keyId, String keyVersionId) {
        super(keyId);
        this.keyVersionId = keyVersionId;
    }

    @Override
    public CloudProvider getCloudProvider() {
        return OracleCloudProvider.INSTANCE;
    }

    public String getKeyVersionId() {
        return keyVersionId;
    }
}
