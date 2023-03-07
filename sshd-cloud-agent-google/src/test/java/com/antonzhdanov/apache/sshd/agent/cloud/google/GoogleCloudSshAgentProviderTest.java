package com.antonzhdanov.apache.sshd.agent.cloud.google;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgent;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.BuiltInSignatureAlgorithm;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import org.apache.sshd.common.session.Session;
import org.testng.annotations.Test;

import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertNotNull;

public class GoogleCloudSshAgentProviderTest {

    @Test
    public void testCreate() {
        // GIVEN
        KeyManagementServiceClient serviceClient = mock(KeyManagementServiceClient.class);
        GoogleCloudSshAgentProvider provider = new GoogleCloudSshAgentProvider(serviceClient);
        Session session = mock(Session.class);
        GoogleCloudKeyInfo cloudKeyInfo = mock(GoogleCloudKeyInfo.class);
        when(cloudKeyInfo.getSignatureAlgorithm()).thenReturn(BuiltInSignatureAlgorithm.ECDSA_SHA_256);

        // WHEN
        CloudSshAgent<GoogleCloudKeyInfo> sshAgent = provider.create(session, cloudKeyInfo);

        // THEN
        assertNotNull(sshAgent);
        verify(cloudKeyInfo, times(1)).getSignatureAlgorithm();
        verify(session, times(1))
                .setSignatureFactories(argThat(list -> list.size() == 1 && list.get(0).getName().equals(BuiltInSignatureAlgorithm.ECDSA_SHA_256.toOpenSshFormat())));
        verifyNoMoreInteractions(session);
    }
}