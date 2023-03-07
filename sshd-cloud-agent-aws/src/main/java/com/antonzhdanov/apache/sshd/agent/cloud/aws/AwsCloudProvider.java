package com.antonzhdanov.apache.sshd.agent.cloud.aws;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudProvider;

public final class AwsCloudProvider implements CloudProvider {

    public static final AwsCloudProvider INSTANCE = new AwsCloudProvider();

    private AwsCloudProvider() {

    }

    @Override
    public String getName() {
        return "AWS";
    }
}
