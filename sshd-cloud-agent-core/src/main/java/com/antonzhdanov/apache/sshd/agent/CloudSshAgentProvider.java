package com.antonzhdanov.apache.sshd.agent;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import org.apache.sshd.common.session.Session;

@FunctionalInterface
public interface CloudSshAgentProvider<K extends CloudKeyInfo> {

    /**
     * Factory method to create cloud specific SSH Agent.
     *
     * @param session client session to modify. Some of cloud provider, e.g. Google, works only with predefined
     *                algorithm due to that it is possible to specify exact algorithm used in signing process
     * @return cloud specific SSH Agent
     */
    CloudSshAgent<K> create(Session session, K keyInfo);
}
