package com.antonzhdanov.apache.sshd.agent.cloud.azure;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgentFactory;
import com.antonzhdanov.apache.sshd.agent.SingleCloudSshAgentFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.AbstractIntegrationTest;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Ignore;
import org.testng.annotations.Test;

public class AzureIntegrationTest extends AbstractIntegrationTest<AzureCloudKeyInfo> {
    @Override
    @DataProvider(parallel = true)
    protected Object[][] testData() {
        return new Object[][]{
                {"azure/RSA-2048.pub", new AzureCloudKeyInfo("https://sshd-cloud-agent-test.vault.azure.net/keys/RSA-2048/00326446c4ac4276be224f0a40665295")},
                {"azure/RSA-3072.pub", new AzureCloudKeyInfo("https://sshd-cloud-agent-test.vault.azure.net/keys/RSA-3072/01a660ce5b9c4fb59d1edbfba78d527e")},
                {"azure/RSA-4096.pub", new AzureCloudKeyInfo("https://sshd-cloud-agent-test.vault.azure.net/keys/RSA-4096/11646053271144719cdf1eea500335a8")},
                {"azure/EC-P256.pub", new AzureCloudKeyInfo("https://sshd-cloud-agent-test.vault.azure.net/keys/EC-P256/504c3c73266f43c492bc787f7b3762ff")},
                {"azure/EC-P384.pub", new AzureCloudKeyInfo("https://sshd-cloud-agent-test.vault.azure.net/keys/EC-P384/331ff303c2c043569e198b116e00788f")},
                {"azure/EC-P521.pub", new AzureCloudKeyInfo("https://sshd-cloud-agent-test.vault.azure.net/keys/EC-P521/1f88fc6e10b04e9c9b3f98fc619742da")}
        };
    }

    @Override
    public void testAuthSucceeded(Object publicKeyObj, AzureCloudKeyInfo keyInfo) throws Exception {
        // Azure free period expired
    }

    @Override
    protected CloudSshAgentFactory<AzureCloudKeyInfo> createCloudFactory() {
        return SingleCloudSshAgentFactory.of(new AzureCloudSshAgentProvider(AzureIntegrationTest::createCryptographyClient));
    }

    public static CryptographyClient createCryptographyClient(AzureCloudKeyInfo keyInfo) {
        return new CryptographyClientBuilder()
                .keyIdentifier(keyInfo.getKeyId())
                .credential(new DefaultAzureCredentialBuilder().build())
                .buildClient();

    }
}
