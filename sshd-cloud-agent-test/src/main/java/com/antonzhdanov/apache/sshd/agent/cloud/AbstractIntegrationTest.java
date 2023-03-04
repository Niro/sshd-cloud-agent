package com.antonzhdanov.apache.sshd.agent.cloud;

import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Duration;
import java.util.stream.Stream;

import static com.antonzhdanov.apache.sshd.agent.cloud.TestUtils.readPublicKey;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class AbstractIntegrationTest<K extends CloudKeyInfo> {

    @ParameterizedTest
    @MethodSource("testData")
    public void testAuthSucceeded(String publicKey, K keyInfo) throws Exception {
        try (OpenSshServerContainer container = new OpenSshServerContainer(readPublicKey(publicKey))) {
            container.start();
            assertTrue(container.isRunning(), "Open SSH Server container did not start");

            try (SshClient sshClient = SshClient.setUpDefaultClient()) {
                sshClient.setAgentFactory(createCloudFactory(keyInfo));
                sshClient.start();

                try (ClientSession session = sshClient.connect("user", "localhost", container.getFirstMappedPort())
                        .verify(Duration.ofSeconds(5)).getSession()) {
                    session.auth().verify(Duration.ofSeconds(5));
                }
            }
        }
    }

    protected abstract Stream<Arguments> testData();

    protected abstract SshAgentFactory createCloudFactory(K keyInfo) throws Exception;
}
