package com.antonzhdanov.apache.sshd.agent.cloud.aws;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgentFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.AbstractIntegrationTest;
import org.apache.sshd.agent.SshAgentFactory;
import org.junit.jupiter.params.provider.Arguments;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

import java.util.stream.Stream;

import static com.antonzhdanov.apache.sshd.agent.cloud.TestUtils.readEnv;

public class AwsIntegrationTest extends AbstractIntegrationTest<AwsCloudKeyInfo> {

    private static final String AWS_ACCESS_KEY_ID_ENVIRONMENT_PROPERTY = "AWS_ACCESS_KEY_ID";
    private static final String AWS_SECRET_ACCESS_KEY_ENVIRONMENT_PROPERTY = "AWS_SECRET_ACCESS_KEY";
    private static final String AWS_REGION_ENVIRONMENT_PROPERTY = "AWS_REGION";

    @Override
    protected Stream<Arguments> testData() {
        return Stream.of(
                Arguments.of("RSA-2048.pub", new AwsCloudKeyInfo("ecde8af1-4f4b-4ccd-be36-7a8b4409b23f"))
        );
    }

    @Override
    protected SshAgentFactory createCloudFactory(AwsCloudKeyInfo keyInfo) {
        return CloudSshAgentFactory.of(new AwsCloudSshAgentProvider(createKmsClient(), keyInfo));
    }

    private KmsClient createKmsClient() {
        String accessKeyId = readEnv(AWS_ACCESS_KEY_ID_ENVIRONMENT_PROPERTY);
        String secretAccessKey = readEnv(AWS_SECRET_ACCESS_KEY_ENVIRONMENT_PROPERTY);
        String region = readEnv(AWS_REGION_ENVIRONMENT_PROPERTY);

        return KmsClient.builder()
                .region(Region.of(region))
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(accessKeyId, secretAccessKey)))
                .build();
    }
}
