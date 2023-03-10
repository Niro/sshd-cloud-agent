package com.antonzhdanov.apache.sshd.agent.cloud.vault.transit;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgentFactory;
import com.antonzhdanov.apache.sshd.agent.SingleCloudSshAgentFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.AbstractIntegrationTest;
import org.testcontainers.containers.wait.strategy.HostPortWaitStrategy;
import org.testcontainers.vault.VaultContainer;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;

import java.util.Arrays;
import java.util.List;

public class VaultTransitIntegrationTest extends AbstractIntegrationTest<VaultTransitCloudKeyInfo> {

    public static final String TOKEN = "TOKEN";
    public static final List<String> KEYS = Arrays.asList("ecdsa-p256", "ecdsa-p384", "ecdsa-p521",
            "rsa-2048", "rsa-3072", "rsa-4096");

    private VaultContainer vaultContainer;
    private TestVaultTransitClient testVaultTransitClient;

    private final boolean fullInit;

    public VaultTransitIntegrationTest() {
        this(true);
    }

    public VaultTransitIntegrationTest(boolean fullInit) {
        this.fullInit = fullInit;
    }

    @BeforeClass
    @Override
    public void init() throws Exception {
        vaultContainer = new VaultContainer("vault")
                .withVaultToken(TOKEN)
                .withInitCommand("secrets enable transit", "write -f transit/keys/my-key");

        vaultContainer.waitingFor(new HostPortWaitStrategy());
        vaultContainer.start();
        testVaultTransitClient = new TestVaultTransitClient(TOKEN, vaultContainer.getHttpHostAddress());

        if (fullInit) {
            super.init();
        }
    }

    @AfterClass
    public void closeVaultContainer() {
        vaultContainer.stop();
    }

    @Override
    @DataProvider(parallel = true)
    public Object[][] testData() {
        return KEYS.stream()
                .map(keyType -> new Object[]{testVaultTransitClient.createKey(keyType), new VaultTransitCloudKeyInfo(keyType)})
                .toArray(Object[][]::new);
    }

    @Override
    protected CloudSshAgentFactory<VaultTransitCloudKeyInfo> createCloudFactory() throws Exception {
        return SingleCloudSshAgentFactory.of(new VaultTransitCloudSshAgentProvider(testVaultTransitClient));
    }

    public TestVaultTransitClient getTestVaultTransitClient() {
        return testVaultTransitClient;
    }
}
