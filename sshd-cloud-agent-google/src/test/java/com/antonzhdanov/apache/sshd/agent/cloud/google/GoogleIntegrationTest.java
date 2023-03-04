package com.antonzhdanov.apache.sshd.agent.cloud.google;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgentFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.AbstractIntegrationTest;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithm;
import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import org.apache.sshd.agent.SshAgentFactory;
import org.junit.jupiter.params.provider.Arguments;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.stream.Stream;

import static com.antonzhdanov.apache.sshd.agent.cloud.TestUtils.readEnv;
import static com.antonzhdanov.apache.sshd.agent.cloud.signature.BuiltInSignatureAlgorithm.ECDSA_SHA_256;
import static com.antonzhdanov.apache.sshd.agent.cloud.signature.BuiltInSignatureAlgorithm.ECDSA_SHA_384;
import static com.antonzhdanov.apache.sshd.agent.cloud.signature.BuiltInSignatureAlgorithm.RSA_PCKS1_V15_SHA256;
import static com.antonzhdanov.apache.sshd.agent.cloud.signature.BuiltInSignatureAlgorithm.RSA_PCKS1_V15_SHA512;

public class GoogleIntegrationTest extends AbstractIntegrationTest<GoogleCloudKeyInfo> {

    private static final String GOOGLE_AUTH_JSON_ENV = "GOOGLE_AUTH_JSON";
    private static final String GOOGLE_PROJECT = "GOOGLE_PROJECT";
    private static final String GOOGLE_LOCATION = "GOOGLE_LOCATION";

    @Override
    protected Stream<Arguments> testData() {
        return Stream.of(
                Arguments.of("RSA-2048-SHA256.pub", createKeyInfo("RSA-2048-SHA256", RSA_PCKS1_V15_SHA256)),
                Arguments.of("RSA-3072-SHA256.pub", createKeyInfo("RSA-3072-SHA256-1", RSA_PCKS1_V15_SHA256)),
                Arguments.of("RSA-4096-SHA256.pub", createKeyInfo("RSA-4096-SHA256", RSA_PCKS1_V15_SHA256)),
                Arguments.of("RSA-4096-SHA512.pub", createKeyInfo("RSA-4096-SHA512", RSA_PCKS1_V15_SHA512)),
                Arguments.of("ECDSA-256.pub", createKeyInfo("ECDSA-256", ECDSA_SHA_256)),
                Arguments.of("ECDSA-384.pub", createKeyInfo("ECDSA-384", ECDSA_SHA_384))
        );
    }

    @Override
    protected SshAgentFactory createCloudFactory(GoogleCloudKeyInfo keyInfo) throws Exception {
        InputStream creds = new ByteArrayInputStream(readEnv(GOOGLE_AUTH_JSON_ENV).getBytes());
        KeyManagementServiceSettings settings = KeyManagementServiceSettings.newBuilder()
                .setCredentialsProvider(FixedCredentialsProvider.create(GoogleCredentials.fromStream(creds)))
                .build();
        KeyManagementServiceClient client = KeyManagementServiceClient.create(settings);

        return CloudSshAgentFactory.of(new GoogleCloudSshAgentProvider(client, keyInfo));
    }

    private GoogleCloudKeyInfo createKeyInfo(String keyName, SignatureAlgorithm algorithm) {
        return GoogleCloudKeyInfo.builder()
                .project(readEnv(GOOGLE_PROJECT))
                .location(readEnv(GOOGLE_LOCATION))
                .keyRing("SSHD-CLOUD-AGENT-TEST")
                .cryptoKey(keyName)
                .cryptoKeyVersion("1")
                .signatureAlgorithm(algorithm)
                .build();
    }
}
