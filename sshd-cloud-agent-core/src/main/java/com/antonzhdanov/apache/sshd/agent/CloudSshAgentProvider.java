package com.antonzhdanov.apache.sshd.agent;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import org.apache.sshd.common.session.Session;

@FunctionalInterface
public interface CloudSshAgentProvider<K extends CloudKeyInfo> {
    CloudSshAgent<K> create(Session session);
}
