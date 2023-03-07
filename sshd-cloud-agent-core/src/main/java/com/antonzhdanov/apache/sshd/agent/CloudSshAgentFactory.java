package com.antonzhdanov.apache.sshd.agent;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.agent.SshAgentServer;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;

import java.io.IOException;

public interface CloudSshAgentFactory<K extends CloudKeyInfo> extends SshAgentFactory {

    @Override
    SshAgentServer createServer(ConnectionService service);

    @Override
    SshAgent createClient(Session session, FactoryManager manager);

    NoExceptionAutoCloseable withKeyInfo(Session session, K keyInfo);

    interface NoExceptionAutoCloseable extends AutoCloseable {
        @Override
        void close();
    }
}
