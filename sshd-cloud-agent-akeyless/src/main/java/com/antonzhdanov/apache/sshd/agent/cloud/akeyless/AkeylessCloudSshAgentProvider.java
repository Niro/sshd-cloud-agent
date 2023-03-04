package com.antonzhdanov.apache.sshd.agent.cloud.akeyless;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgent;
import com.antonzhdanov.apache.sshd.agent.CloudSshAgentProvider;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.akeyless.client.AkeylessApiClient;
import com.antonzhdanov.apache.sshd.agent.cloud.akeyless.client.DefaultAkeylessApiClient;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.BuiltInSignatureAlgorithm;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.signature.BuiltinSignatures;

import java.util.Collections;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

public class AkeylessCloudSshAgentProvider implements CloudSshAgentProvider<AkeylessCloudKeyInfo> {

    private final AkeylessApiClient akeylessApiClient;
    private final AkeylessCloudKeyInfo keyInfo;

    public AkeylessCloudSshAgentProvider(String token, AkeylessCloudKeyInfo keyInfo) {
        this(new DefaultAkeylessApiClient(requireNonNull(token, "token")), keyInfo);
    }

    public AkeylessCloudSshAgentProvider(AkeylessApiClient akeylessApiClient, AkeylessCloudKeyInfo keyInfo) {
        this.akeylessApiClient = requireNonNull(akeylessApiClient, "akeylessApiClient");
        this.keyInfo = requireNonNull(keyInfo, "keyInfo");
    }

    @Override
    public CloudSshAgent<AkeylessCloudKeyInfo> create(Session session) {
        session.setSignatureFactories(Collections.singletonList(BuiltinSignatures.rsaSHA256));

        return new CloudSshAgent<>(new AkeylessSigner(akeylessApiClient),
                new AkeylessPublicKeyLoader(akeylessApiClient, new CloudPublicKeyFactory()),
                keyInfo,
                algo -> Optional.of(BuiltInSignatureAlgorithm.RSA_PCKS1_V15_SHA256));

    }
}
