package com.antonzhdanov.apache.sshd.agent.integration.google;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgentFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.implementation.google.GoogleCloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.BuiltInSignatureAlgorithm;
import com.antonzhdanov.apache.sshd.agent.integration.AbstractIntegrationTest;
import com.antonzhdanov.apache.sshd.agent.integration.TestUtils;
import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.common.signature.BuiltinSignatures;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;

public class GoogleIntegrationTest extends AbstractIntegrationTest {
    private static final List<GoogleCloudKeyInfo> KEY_INFOS = Collections.singletonList(GoogleCloudKeyInfo.builder()
            .project("hip-orbit-320910")
            .location("europe-west3")
            .keyRing("Test")
            .cryptoKey("test_sshd")
            .cryptoKeyVersion("1")
            .signatureAlgorithm(BuiltInSignatureAlgorithm.RSA_SHA256)
            .build());

    public GoogleIntegrationTest() {
        super("google_public_key.pub");
    }

    @Override
    protected SshAgentFactory createCloudFactory() throws Exception {
        InputStream creds = new ByteArrayInputStream(TestUtils.readEnv("GOOGLE_AUTH_JSON").getBytes());
        KeyManagementServiceSettings settings = KeyManagementServiceSettings.newBuilder()
                .setCredentialsProvider(FixedCredentialsProvider.create(GoogleCredentials.fromStream(creds)))
                .build();
        KeyManagementServiceClient client = KeyManagementServiceClient.create(settings);

        return CloudSshAgentFactory.forGoogle(client, KEY_INFOS);
    }

    @Override
    protected void prepareClient(SshClient sshClient) {
        sshClient.setSignatureFactories(Collections.singletonList(BuiltinSignatures.rsaSHA256));
    }
}
