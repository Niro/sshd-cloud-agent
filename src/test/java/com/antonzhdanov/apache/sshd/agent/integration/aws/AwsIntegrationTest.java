package com.antonzhdanov.apache.sshd.agent.integration.aws;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgentFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.implementation.aws.AwsCloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.integration.AbstractIntegrationTest;
import org.apache.sshd.agent.SshAgentFactory;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsAsyncClient;

import java.util.Collections;
import java.util.List;

import static com.antonzhdanov.apache.sshd.agent.integration.TestUtils.readEnv;

public class AwsIntegrationTest extends AbstractIntegrationTest {

    private static final String AWS_ACCESS_KEY_ID_ENVIRONMENT_PROPERTY = "AWS_ACCESS_KEY_ID";
    private static final String AWS_SECRET_ACCESS_KEY_ENVIRONMENT_PROPERTY = "AWS_SECRET_ACCESS_KEY";
    private static final String AWS_REGION_ENVIRONMENT_PROPERTY = "AWS_REGION";

    private static final List<AwsCloudKeyInfo> KEY_INFOS = Collections.singletonList(new AwsCloudKeyInfo("ecde8af1-4f4b-4ccd-be36-7a8b4409b23f"));

    public AwsIntegrationTest() {
        super("aws_public_key.pub");
    }

    @Override
    protected SshAgentFactory createCloudFactory() {
        return CloudSshAgentFactory.fowAws(createKmsAsyncClient(), KEY_INFOS);
    }

    private KmsAsyncClient createKmsAsyncClient() {
        String accessKeyId = readEnv(AWS_ACCESS_KEY_ID_ENVIRONMENT_PROPERTY);
        String secretAccessKey = readEnv(AWS_SECRET_ACCESS_KEY_ENVIRONMENT_PROPERTY);
        String region = readEnv(AWS_REGION_ENVIRONMENT_PROPERTY);

        return KmsAsyncClient.builder()
                .region(Region.of(region))
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(accessKeyId, secretAccessKey)))
                .build();
    }
}
