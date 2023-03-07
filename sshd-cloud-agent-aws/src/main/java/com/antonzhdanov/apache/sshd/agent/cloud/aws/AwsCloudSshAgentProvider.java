package com.antonzhdanov.apache.sshd.agent.cloud.aws;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgent;
import com.antonzhdanov.apache.sshd.agent.CloudSshAgentProvider;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudProvider;
import com.antonzhdanov.apache.sshd.agent.cloud.key.CloudPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.key.JcaPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.DefaultSignaturePostProcessor;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SshdSignatureAlgorithmMapper;
import org.apache.sshd.common.session.Session;
import software.amazon.awssdk.services.kms.KmsClient;

import static java.util.Objects.requireNonNull;

public class AwsCloudSshAgentProvider implements CloudSshAgentProvider<AwsCloudKeyInfo> {

    private final KmsClient kmsClient;

    public AwsCloudSshAgentProvider(KmsClient kmsClient) {
        this.kmsClient = requireNonNull(kmsClient, "kmsClient");
    }

    @Override
    public CloudSshAgent<AwsCloudKeyInfo> create(Session session, AwsCloudKeyInfo keyInfo) {
        return new CloudSshAgent<>(new AwsSigner(kmsClient, new AwsSignatureAlgorithmMapper()),
                new AwsPublicKeyLoader(kmsClient, new CloudPublicKeyFactory<>(new JcaPublicKeyFactory())),
                new DefaultSignaturePostProcessor(),
                keyInfo, new SshdSignatureAlgorithmMapper());
    }

    @Override
    public CloudProvider getCloudProvider() {
        return AwsCloudProvider.INSTANCE;
    }
}
