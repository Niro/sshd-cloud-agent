package com.antonzhdanov.apache.sshd.agent.cloud.google;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudProvider;

public class GoogleCloudProvider implements CloudProvider {

    public static final GoogleCloudProvider INSTANCE = new GoogleCloudProvider();

    private GoogleCloudProvider() {

    }

    @Override
    public String getName() {
        return "Google";
    }
}
