package com.antonzhdanov.apache.sshd.agent;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.agent.SshAgentServer;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.channel.ChannelFactory;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;

import java.util.Collections;
import java.util.List;

import static java.util.Objects.requireNonNull;

public class CloudSshAgentFactory<K extends CloudKeyInfo> implements SshAgentFactory {

    private final CloudSshAgentProvider<K> sshAgentProvider;

    private CloudSshAgentFactory(CloudSshAgentProvider<K> sshAgentProvider) {
        this.sshAgentProvider = requireNonNull(sshAgentProvider, "sshAgentProvider");
    }

    public static <T extends CloudKeyInfo> CloudSshAgentFactory<T> of(CloudSshAgentProvider<T> agentProvider) {
        return new CloudSshAgentFactory<>(agentProvider);
    }

    @Override
    public List<ChannelFactory> getChannelForwardingFactories(FactoryManager manager) {
        return Collections.emptyList();
    }

    @Override
    public SshAgent createClient(Session session, FactoryManager manager) {
        return sshAgentProvider.create(session);
    }

    @Override
    public SshAgentServer createServer(ConnectionService service) {
        throw new UnsupportedOperationException();
    }
}
