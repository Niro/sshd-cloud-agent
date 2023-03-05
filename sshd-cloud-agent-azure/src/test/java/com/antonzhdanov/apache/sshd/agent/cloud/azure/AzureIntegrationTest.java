package com.antonzhdanov.apache.sshd.agent.cloud.azure;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgentFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.AbstractIntegrationTest;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import org.apache.sshd.agent.SshAgentFactory;
import org.junit.jupiter.params.provider.Arguments;

import java.util.stream.Stream;

public class AzureIntegrationTest extends AbstractIntegrationTest<AzureCloudKeyInfo> {
    @Override
    protected Stream<Arguments> testData() {
        return Stream.of(
                Arguments.of("RSA-2048.pub", new AzureCloudKeyInfo("https://sshd-cloud-agent-test.vault.azure.net/keys/RSA-2048/00326446c4ac4276be224f0a40665295")),
                Arguments.of("RSA-3072.pub", new AzureCloudKeyInfo("https://sshd-cloud-agent-test.vault.azure.net/keys/RSA-3072/01a660ce5b9c4fb59d1edbfba78d527e")),
                Arguments.of("RSA-4096.pub", new AzureCloudKeyInfo("https://sshd-cloud-agent-test.vault.azure.net/keys/RSA-4096/11646053271144719cdf1eea500335a8")),
                Arguments.of("EC-P256.pub", new AzureCloudKeyInfo("https://sshd-cloud-agent-test.vault.azure.net/keys/EC-P256/504c3c73266f43c492bc787f7b3762ff")),
                Arguments.of("EC-P384.pub", new AzureCloudKeyInfo("https://sshd-cloud-agent-test.vault.azure.net/keys/EC-P384/331ff303c2c043569e198b116e00788f")),
                Arguments.of("EC-P521.pub", new AzureCloudKeyInfo("https://sshd-cloud-agent-test.vault.azure.net/keys/EC-P521/1f88fc6e10b04e9c9b3f98fc619742da"))
        );
    }

    @Override
    protected SshAgentFactory createCloudFactory(AzureCloudKeyInfo keyInfo) {
        return CloudSshAgentFactory.of(new AzureCloudSshAgentProvider(this::createCryptographyClient, keyInfo));
    }

    private CryptographyClient createCryptographyClient(AzureCloudKeyInfo keyInfo) {
        return new CryptographyClientBuilder()
                .keyIdentifier(keyInfo.getKeyId())
                .credential(new DefaultAzureCredentialBuilder().build())
                .buildClient();

    }
}
