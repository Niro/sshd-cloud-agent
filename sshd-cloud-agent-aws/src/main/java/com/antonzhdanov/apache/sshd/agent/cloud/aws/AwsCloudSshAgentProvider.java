package com.antonzhdanov.apache.sshd.agent.cloud.aws;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgent;
import com.antonzhdanov.apache.sshd.agent.CloudSshAgentProvider;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.DefaultSignaturePostProcessor;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SshdSignatureAlgorithmMapper;
import org.apache.sshd.common.session.Session;
import software.amazon.awssdk.services.kms.KmsClient;

import static java.util.Objects.requireNonNull;

public class AwsCloudSshAgentProvider implements CloudSshAgentProvider<AwsCloudKeyInfo> {

    private final KmsClient kmsClient;
    private final AwsCloudKeyInfo keyInfo;

    public AwsCloudSshAgentProvider(KmsClient kmsClient, AwsCloudKeyInfo keyInfo) {
        this.kmsClient = requireNonNull(kmsClient, "kmsClient");
        this.keyInfo = requireNonNull(keyInfo, "keyInfo");
    }

    @Override
    public CloudSshAgent<AwsCloudKeyInfo> create(Session session) {
        return new CloudSshAgent<>(new AwsSigner(kmsClient, new AwsSignatureAlgorithmMapper()),
                new AwsPublicKeyLoader(kmsClient, new CloudPublicKeyFactory<>()),
                new DefaultSignaturePostProcessor(),
                keyInfo, new SshdSignatureAlgorithmMapper());
    }
}
