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
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Objects.requireNonNull;

public class CloudSshAgentFactory<K extends CloudKeyInfo> implements SshAgentFactory {

    private final CloudSshAgentProvider<K> sshAgentProvider;
    private final Map<Session, K> keyInfosPerSession = new ConcurrentHashMap<>();

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
        K keyInfo = Optional.ofNullable(keyInfosPerSession.get(session)).orElseThrow();

        return sshAgentProvider.create(session, keyInfo);
    }

    @Override
    public SshAgentServer createServer(ConnectionService service) {
        throw new UnsupportedOperationException();
    }

    public NoExceptionAutoCloseable withKeyInfo(Session session, K keyInfo) {
        requireNonNull(session);
        requireNonNull(keyInfo);

        keyInfosPerSession.put(session, keyInfo);

        return () -> keyInfosPerSession.remove(session);
    }

    public interface NoExceptionAutoCloseable extends AutoCloseable {
        @Override
        void close();
    }
}
