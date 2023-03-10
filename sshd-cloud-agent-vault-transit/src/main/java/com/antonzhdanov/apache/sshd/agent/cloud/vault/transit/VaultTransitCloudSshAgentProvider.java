package com.antonzhdanov.apache.sshd.agent.cloud.vault.transit;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgent;
import com.antonzhdanov.apache.sshd.agent.CloudSshAgentProvider;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudProvider;
import com.antonzhdanov.apache.sshd.agent.cloud.key.CloudPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.key.JcaPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.DefaultSignaturePostProcessor;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SshdSignatureAlgorithmMapper;
import org.apache.sshd.common.session.Session;

import java.util.Objects;

public class VaultTransitCloudSshAgentProvider implements CloudSshAgentProvider<VaultTransitCloudKeyInfo> {

    private final VaultTransitClient vaultTransitClient;

    public VaultTransitCloudSshAgentProvider(VaultTransitClient vaultTransitClient) {
        this.vaultTransitClient = Objects.requireNonNull(vaultTransitClient, "vaultTransitClient");
    }

    @Override
    public CloudSshAgent<VaultTransitCloudKeyInfo> create(Session session, VaultTransitCloudKeyInfo keyInfo) {
        return new CloudSshAgent<>(
                new VaultTransitSigner(vaultTransitClient, new VaultTransitSignatureAlgorithmMapper()),
                new VaultTransitPublicKeyLoader(vaultTransitClient, new CloudPublicKeyFactory<>(new JcaPublicKeyFactory())),
                new DefaultSignaturePostProcessor(),
                keyInfo,
                new SshdSignatureAlgorithmMapper()
        );
    }

    @Override
    public CloudProvider getCloudProvider() {
        return VaultTransitCloudProvider.INSTANCE;
    }
}
