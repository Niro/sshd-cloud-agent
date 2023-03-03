package com.antonzhdanov.apache.sshd.agent.cloud.aws;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgent;
import com.antonzhdanov.apache.sshd.agent.CloudSshAgentProvider;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SshdSignatureAlgorithmMapper;
import software.amazon.awssdk.services.kms.KmsAsyncClient;

import java.util.Collections;
import java.util.List;

import static java.util.Objects.requireNonNull;

public class AwsCloudSshAgentProvider implements CloudSshAgentProvider<AwsCloudKeyInfo> {

    private final KmsAsyncClient kmsAsyncClient;
    private final List<AwsCloudKeyInfo> keyInfos;

    public AwsCloudSshAgentProvider(KmsAsyncClient kmsAsyncClient, List<AwsCloudKeyInfo> keyInfos) {
        this.kmsAsyncClient = requireNonNull(kmsAsyncClient, "kmsAsyncClient");
        this.keyInfos = Collections.unmodifiableList(requireNonNull(keyInfos, "keyInfos"));
    }

    @Override
    public CloudSshAgent<AwsCloudKeyInfo> create() {
        return new CloudSshAgent<>(new AwsSigner(kmsAsyncClient, new AwsSignatureAlgorithmMapper()),
                new AwsPublicKeyLoader(kmsAsyncClient, new CloudPublicKeyFactory()),
                keyInfos, new SshdSignatureAlgorithmMapper());
    }
}
