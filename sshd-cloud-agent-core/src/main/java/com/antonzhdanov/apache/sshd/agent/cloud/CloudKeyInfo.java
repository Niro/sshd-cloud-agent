package com.antonzhdanov.apache.sshd.agent.cloud;

public interface CloudKeyInfo {
    String getComment();

    CloudProvider getCloudProvider();
}
