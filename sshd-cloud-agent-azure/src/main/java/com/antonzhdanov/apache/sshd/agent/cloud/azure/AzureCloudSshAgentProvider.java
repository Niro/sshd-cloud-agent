package com.antonzhdanov.apache.sshd.agent.cloud.azure;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgent;
import com.antonzhdanov.apache.sshd.agent.CloudSshAgentProvider;
import com.antonzhdanov.apache.sshd.agent.cloud.key.CloudPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.azure.signature.JwaSignaturePostProcessor;
import com.antonzhdanov.apache.sshd.agent.cloud.key.JcaPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SshdSignatureAlgorithmMapper;
import org.apache.sshd.common.session.Session;

import static java.util.Objects.requireNonNull;

public class AzureCloudSshAgentProvider implements CloudSshAgentProvider<AzureCloudKeyInfo> {

    private final CryptographyClientProvider cryptographyClientProvider;
    private final AzureCloudKeyInfo keyInfo;

    public AzureCloudSshAgentProvider(CryptographyClientProvider cryptographyClientProvider, AzureCloudKeyInfo keyInfo) {
        this.cryptographyClientProvider = requireNonNull(cryptographyClientProvider, "cryptographyClientProvider");
        this.keyInfo = requireNonNull(keyInfo, "keyInfo");
    }

    @Override
    public CloudSshAgent<AzureCloudKeyInfo> create(Session session) {
        return new CloudSshAgent<>(
                new AzureSigner(cryptographyClientProvider, new AzureSignatureAlgorithmMapper()),
                new AzurePublicKeyLoader(cryptographyClientProvider, new CloudPublicKeyFactory<>(new JcaPublicKeyFactory())),
                new JwaSignaturePostProcessor(),
                keyInfo,
                new SshdSignatureAlgorithmMapper()
        );
    }
}
