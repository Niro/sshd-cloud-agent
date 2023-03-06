package com.antonzhdanov.apache.sshd.agent.cloud.key;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;

public class TestCloudKeyInfo implements CloudKeyInfo {

    private final String id;

    public TestCloudKeyInfo(String id) {
        this.id = id;
    }

    @Override
    public String getComment() {
        return "TEST";
    }
}
