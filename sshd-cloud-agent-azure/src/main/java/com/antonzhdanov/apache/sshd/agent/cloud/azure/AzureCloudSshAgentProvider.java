package com.antonzhdanov.apache.sshd.agent.cloud.azure;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgent;
import com.antonzhdanov.apache.sshd.agent.CloudSshAgentProvider;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudProvider;
import com.antonzhdanov.apache.sshd.agent.cloud.azure.signature.JsonWebSignaturePostProcessor;
import com.antonzhdanov.apache.sshd.agent.cloud.key.CloudPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.key.JcaPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SshdSignatureAlgorithmMapper;
import org.apache.sshd.common.session.Session;

import static java.util.Objects.requireNonNull;

public class AzureCloudSshAgentProvider implements CloudSshAgentProvider<AzureCloudKeyInfo> {

    private final CryptographyClientProvider cryptographyClientProvider;

    public AzureCloudSshAgentProvider(CryptographyClientProvider cryptographyClientProvider) {
        this.cryptographyClientProvider = requireNonNull(cryptographyClientProvider, "cryptographyClientProvider");
    }

    @Override
    public CloudSshAgent<AzureCloudKeyInfo> create(Session session, AzureCloudKeyInfo keyInfo) {
        return new CloudSshAgent<>(
                new AzureSigner(cryptographyClientProvider, new AzureSignatureAlgorithmMapper()),
                new AzurePublicKeyLoader(cryptographyClientProvider, new CloudPublicKeyFactory<>(new JcaPublicKeyFactory())),
                new JsonWebSignaturePostProcessor(),
                keyInfo,
                new SshdSignatureAlgorithmMapper()
        );
    }

    @Override
    public CloudProvider getCloudProvider() {
        return AzureCloudProvider.INSTANCE;
    }
}
