package com.antonzhdanov.apache.sshd.agent.cloud.aws;

import com.antonzhdanov.apache.sshd.agent.cloud.AbstractCloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudProvider;

public class AwsCloudKeyInfo extends AbstractCloudKeyInfo {

    public AwsCloudKeyInfo(String keyId) {
        super(keyId);
    }

    @Override
    public String getComment() {
        return "AWS " + getKeyId();
    }

    @Override
    public CloudProvider getCloudProvider() {
        return AwsCloudProvider.INSTANCE;
    }

}
