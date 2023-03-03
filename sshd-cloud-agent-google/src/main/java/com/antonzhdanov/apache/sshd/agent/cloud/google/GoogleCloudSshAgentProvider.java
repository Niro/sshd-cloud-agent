package com.antonzhdanov.apache.sshd.agent.cloud.google;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgent;
import com.antonzhdanov.apache.sshd.agent.CloudSshAgentProvider;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SshdSignatureAlgorithmMapper;
import com.google.cloud.kms.v1.KeyManagementServiceClient;

import java.util.Collections;
import java.util.List;

import static java.util.Objects.requireNonNull;

public class GoogleCloudSshAgentProvider implements CloudSshAgentProvider<GoogleCloudKeyInfo> {

    private final KeyManagementServiceClient keyManagementServiceClient;
    private final List<GoogleCloudKeyInfo> keyInfos;

    public GoogleCloudSshAgentProvider(KeyManagementServiceClient keyManagementServiceClient, List<GoogleCloudKeyInfo> keyInfos) {
        this.keyManagementServiceClient = requireNonNull(keyManagementServiceClient, "keyManagementServiceClient");
        this.keyInfos = Collections.unmodifiableList(requireNonNull(keyInfos, "keyInfos"));
    }

    @Override
    public CloudSshAgent<GoogleCloudKeyInfo> create() {
        return new CloudSshAgent<>(new GoogleSigner(keyManagementServiceClient),
                new GooglePublicKeyLoader(keyManagementServiceClient, new CloudPublicKeyFactory()),
                keyInfos, new SshdSignatureAlgorithmMapper());
    }
}
