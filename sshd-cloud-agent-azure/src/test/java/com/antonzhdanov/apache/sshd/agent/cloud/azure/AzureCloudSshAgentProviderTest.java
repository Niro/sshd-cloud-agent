package com.antonzhdanov.apache.sshd.agent.cloud.azure;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgent;
import org.apache.sshd.common.session.Session;
import org.testng.annotations.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.testng.Assert.assertNotNull;

public class AzureCloudSshAgentProviderTest {

    @Test
    public void testCreate() {
        // GIVEN
        AzureCloudSshAgentProvider provider = new AzureCloudSshAgentProvider(mock(CryptographyClientProvider.class));
        Session session = mock(Session.class);
        AzureCloudKeyInfo cloudKeyInfo = mock(AzureCloudKeyInfo.class);

        // WHEN
        CloudSshAgent<AzureCloudKeyInfo> sshAgent = provider.create(session, cloudKeyInfo);

        // THEN
        assertNotNull(sshAgent);
        verifyNoInteractions(session);
        verifyNoInteractions(cloudKeyInfo);
    }
}