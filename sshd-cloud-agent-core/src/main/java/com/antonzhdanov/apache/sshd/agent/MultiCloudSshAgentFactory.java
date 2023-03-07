package com.antonzhdanov.apache.sshd.agent;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudProvider;
import com.antonzhdanov.apache.sshd.agent.cloud.exception.CloudSshAgentException;
import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.agent.SshAgentServer;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.channel.ChannelFactory;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;

public class MultiCloudSshAgentFactory implements CloudSshAgentFactory<CloudKeyInfo> {

    private final Map<CloudProvider, CloudSshAgentFactory<? extends CloudKeyInfo>> factories;
    private final Map<Session, CloudSshAgentFactory<CloudKeyInfo>> factoriesPerSession = new ConcurrentHashMap<>();

    private MultiCloudSshAgentFactory(List<CloudSshAgentProvider<? extends CloudKeyInfo>> providers) {
        this.factories = providers.stream()
                .collect(Collectors.toUnmodifiableMap(CloudSshAgentProvider::getCloudProvider, SingleCloudSshAgentFactory::of));
    }

    public static CloudSshAgentFactory<CloudKeyInfo> of(List<CloudSshAgentProvider<? extends CloudKeyInfo>> providers) {
        return new MultiCloudSshAgentFactory(providers);
    }

    @Override
    public List<ChannelFactory> getChannelForwardingFactories(FactoryManager manager) {
        return Collections.emptyList();
    }

    @Override
    public SshAgent createClient(Session session, FactoryManager manager) {
        return factoriesPerSession.get(session).createClient(session, manager);
    }

    @Override
    public SshAgentServer createServer(ConnectionService service) {
        throw new UnsupportedOperationException();
    }

    public SingleCloudSshAgentFactory.NoExceptionAutoCloseable withKeyInfo(Session session, CloudKeyInfo keyInfo) {
        requireNonNull(session);
        requireNonNull(keyInfo);

        CloudSshAgentFactory<CloudKeyInfo> agentFactory = (CloudSshAgentFactory<CloudKeyInfo>) factories.get(keyInfo.getCloudProvider());
        if (agentFactory == null) {
            throw new CloudSshAgentException("No factory for " + keyInfo.getCloudProvider().getName());
        }

        factoriesPerSession.put(session, agentFactory);

        return new SingleCloudSshAgentFactory.NoExceptionAutoCloseable() {
            private final SingleCloudSshAgentFactory.NoExceptionAutoCloseable inner = agentFactory.withKeyInfo(session, keyInfo);

            @Override
            public void close() {
                factoriesPerSession.remove(session);
                inner.close();
            }
        };
    }
}
