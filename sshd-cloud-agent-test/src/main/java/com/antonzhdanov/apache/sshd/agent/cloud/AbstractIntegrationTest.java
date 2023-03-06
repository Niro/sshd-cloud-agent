package com.antonzhdanov.apache.sshd.agent.cloud;

import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.testng.annotations.Test;

import java.time.Duration;

import static com.antonzhdanov.apache.sshd.agent.cloud.TestUtils.readPublicKey;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public abstract class AbstractIntegrationTest<K extends CloudKeyInfo> {

    private static final String ECHO_STRING = String.valueOf(System.currentTimeMillis());

    @Test(dataProvider = "testData")
    public void testAuthSucceeded(String publicKey, K keyInfo) throws Exception {
        try (OpenSshServerContainer container = new OpenSshServerContainer(readPublicKey(publicKey))) {
            container.start();
            assertTrue(container.isRunning(), "Open SSH Server container did not start");

            try (SshClient sshClient = SshClient.setUpDefaultClient()) {
                sshClient.setAgentFactory(createCloudFactory(keyInfo));
                sshClient.start();

                try (ClientSession session = sshClient.connect("user", "localhost", container.getFirstMappedPort())
                        .verify(Duration.ofSeconds(5)).getSession()) {
                    session.auth().verify(Duration.ofSeconds(10));

                    assertEquals(ECHO_STRING,
                            session.executeRemoteCommand("echo " + ECHO_STRING).replace("\n", ""));
                }
            }
        }
    }

    protected abstract Object[][] testData();

    protected abstract SshAgentFactory createCloudFactory(K keyInfo) throws Exception;
}
