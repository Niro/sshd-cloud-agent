package com.antonzhdanov.apache.sshd.agent.cloud.google;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgent;
import com.antonzhdanov.apache.sshd.agent.CloudSshAgentProvider;
import com.antonzhdanov.apache.sshd.agent.cloud.key.CloudPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.key.JcaPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.DefaultSignaturePostProcessor;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.signature.BuiltinSignatures;

import java.util.Collections;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

public class GoogleCloudSshAgentProvider implements CloudSshAgentProvider<GoogleCloudKeyInfo> {

    private final KeyManagementServiceClient keyManagementServiceClient;

    public GoogleCloudSshAgentProvider(KeyManagementServiceClient keyManagementServiceClient) {
        this.keyManagementServiceClient = requireNonNull(keyManagementServiceClient, "keyManagementServiceClient");
    }

    @Override
    public CloudSshAgent<GoogleCloudKeyInfo> create(Session session, GoogleCloudKeyInfo keyInfo) {
        session.setSignatureFactories(Collections.singletonList(BuiltinSignatures.resolveFactory(keyInfo.getSignatureAlgorithm().toOpenSshFormat())));

        return new CloudSshAgent<>(new GoogleSigner(keyManagementServiceClient),
                new GooglePublicKeyLoader(keyManagementServiceClient, new CloudPublicKeyFactory<>(new JcaPublicKeyFactory())),
                new DefaultSignaturePostProcessor(),
                keyInfo,
                algo -> Optional.of(keyInfo.getSignatureAlgorithm()));
    }
}
