package com.antonzhdanov.apache.sshd.agent.cloud;

import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;

import static com.antonzhdanov.apache.sshd.agent.cloud.TestUtils.readPublicKey;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Testcontainers
public abstract class AbstractIntegrationTest {
    @Container
    protected final OpenSshServerContainer sshServerContainer;

    protected AbstractIntegrationTest(String publicKeyName) {
        this.sshServerContainer = new OpenSshServerContainer(readPublicKey(publicKeyName));
    }

    @BeforeEach
    public void ensureThatContainerIsRunning() {
        assertTrue(sshServerContainer.isRunning(), "Open SSH Server container did not start");
    }

    @Test
    public void testAuthSucceeded() throws Exception {
        try (SshClient sshClient = SshClient.setUpDefaultClient()) {
            sshClient.setAgentFactory(createCloudFactory());
            prepareClient(sshClient);
            sshClient.start();

            try (ClientSession session = sshClient.connect("user", "localhost", 2222).verify(Duration.ofSeconds(5)).getSession()) {
                session.auth().verify(Duration.ofSeconds(5));
            }
        }
    }

    protected abstract SshAgentFactory createCloudFactory() throws Exception;

    protected void prepareClient(SshClient sshClient) {

    }
}
