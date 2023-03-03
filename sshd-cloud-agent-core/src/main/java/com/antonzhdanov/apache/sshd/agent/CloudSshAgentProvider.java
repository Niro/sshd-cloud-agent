package com.antonzhdanov.apache.sshd.agent;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;

@FunctionalInterface
public interface CloudSshAgentProvider<K extends CloudKeyInfo> {
    CloudSshAgent<K> create();
}
