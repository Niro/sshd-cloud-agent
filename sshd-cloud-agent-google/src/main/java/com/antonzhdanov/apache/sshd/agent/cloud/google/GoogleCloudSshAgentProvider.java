package com.antonzhdanov.apache.sshd.agent.cloud.google;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgent;
import com.antonzhdanov.apache.sshd.agent.CloudSshAgentProvider;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKeyFactory;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.signature.BuiltinSignatures;

import java.util.Collections;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

public class GoogleCloudSshAgentProvider implements CloudSshAgentProvider<GoogleCloudKeyInfo> {

    private final KeyManagementServiceClient keyManagementServiceClient;
    private final GoogleCloudKeyInfo keyInfo;

    public GoogleCloudSshAgentProvider(KeyManagementServiceClient keyManagementServiceClient, GoogleCloudKeyInfo keyInfo) {
        this.keyManagementServiceClient = requireNonNull(keyManagementServiceClient, "keyManagementServiceClient");
        this.keyInfo = requireNonNull(keyInfo, "keyInfos");
    }

    @Override
    public CloudSshAgent<GoogleCloudKeyInfo> create(Session session) {
        session.setSignatureFactories(Collections.singletonList(BuiltinSignatures.resolveFactory(keyInfo.getSignatureAlgorithm().toKnownAlgorithm())));

        return new CloudSshAgent<>(new GoogleSigner(keyManagementServiceClient),
                new GooglePublicKeyLoader(keyManagementServiceClient, new CloudPublicKeyFactory()),
                keyInfo,
                algo -> Optional.of(keyInfo.getSignatureAlgorithm()));
    }
}
