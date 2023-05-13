package com.antonzhdanov.apache.sshd.agent.cloud;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgentFactory;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.security.PublicKey;
import java.time.Duration;

import static com.antonzhdanov.apache.sshd.agent.cloud.TestUtils.readPublicKey;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public abstract class AbstractIntegrationTest<K extends CloudKeyInfo> {

    private static final String ECHO_STRING = String.valueOf(System.currentTimeMillis());

    private final SshClient sshClient = SshClient.setUpDefaultClient();
    private CloudSshAgentFactory<K> cloudFactory;

    @BeforeClass
    public void init() throws Exception {
        cloudFactory = createCloudFactory();
        sshClient.setAgentFactory(cloudFactory);
        sshClient.start();
    }

    @AfterClass
    public void close() throws Exception {
        sshClient.close();
    }

    @Test(dataProvider = "testData")
    public void testAuthSucceeded(Object publicKeyObj, K keyInfo) throws Exception {
        PublicKey publicKey;
        if (publicKeyObj instanceof PublicKey) {
            publicKey = (PublicKey) publicKeyObj;
        } else if (publicKeyObj instanceof String){
            publicKey = readPublicKey((String) publicKeyObj);
        } else {
            throw new RuntimeException("Unknown argument type " + publicKeyObj.getClass().getName());
        }

        try (OpenSshServerContainer container = new OpenSshServerContainer(publicKey)) {
            assertTrue(container.isRunning(), "Open SSH Server container did not start");

            try (ClientSession session = sshClient.connect("user", "localhost", container.getFirstMappedPort())
                    .verify(Duration.ofSeconds(5)).getSession()) {
                try (var unused = cloudFactory.withKeyInfo(session, keyInfo)) {
                    session.auth().verify(Duration.ofSeconds(10));
                }

                assertEquals(ECHO_STRING,
                        session.executeRemoteCommand("echo " + ECHO_STRING).replace("\n", ""));
            }
        }
    }

    protected abstract Object[][] testData();

    protected abstract CloudSshAgentFactory<K> createCloudFactory() throws Exception;
}
