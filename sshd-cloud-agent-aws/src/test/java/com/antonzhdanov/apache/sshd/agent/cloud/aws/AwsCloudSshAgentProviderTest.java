package com.antonzhdanov.apache.sshd.agent.cloud.aws;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgent;
import org.apache.sshd.common.session.Session;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.kms.KmsClient;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.testng.Assert.assertNotNull;

public class AwsCloudSshAgentProviderTest {

    @Test
    public void testCreate() {
        // GIVEN
        KmsClient kmsClient = mock(KmsClient.class);
        AwsCloudSshAgentProvider provider = new AwsCloudSshAgentProvider(kmsClient);
        Session session = mock(Session.class);
        AwsCloudKeyInfo cloudKeyInfo = mock(AwsCloudKeyInfo.class);

        // WHEN
        CloudSshAgent<AwsCloudKeyInfo> sshAgent = provider.create(session, cloudKeyInfo);

        // THEN
        assertNotNull(sshAgent);
        verifyNoInteractions(session);
        verifyNoInteractions(cloudKeyInfo);
    }
}