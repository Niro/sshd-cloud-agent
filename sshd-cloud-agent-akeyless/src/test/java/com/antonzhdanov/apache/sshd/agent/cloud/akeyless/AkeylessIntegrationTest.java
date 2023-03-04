package com.antonzhdanov.apache.sshd.agent.cloud.akeyless;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgentFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.AbstractIntegrationTest;
import org.apache.sshd.agent.SshAgentFactory;
import org.junit.jupiter.params.provider.Arguments;

import java.util.stream.Stream;

public class AkeylessIntegrationTest extends AbstractIntegrationTest<AkeylessCloudKeyInfo> {
    @Override
    protected Stream<Arguments> testData() {
        return Stream.of(
                Arguments.of("RSA-4096.pub", new AkeylessCloudKeyInfo("test"))
        );
    }

    @Override
    protected SshAgentFactory createCloudFactory(AkeylessCloudKeyInfo keyInfo) throws Exception {
        return CloudSshAgentFactory.of(new AkeylessCloudSshAgentProvider("t-c3e23d77d4fb7553b1ef012f79a276e6", keyInfo));
    }
}
