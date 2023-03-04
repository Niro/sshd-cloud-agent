package com.antonzhdanov.apache.sshd.agent.cloud.akeyless;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.Signer;
import com.antonzhdanov.apache.sshd.agent.cloud.akeyless.client.AkeylessApiClient;
import com.antonzhdanov.apache.sshd.agent.cloud.akeyless.client.api.response.SignResponse;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithm;

import java.security.PublicKey;
import java.util.Base64;
import java.util.Objects;

public class AkeylessSigner implements Signer<AkeylessCloudKeyInfo> {

    private final AkeylessApiClient akeylessApiClient;

    public AkeylessSigner(AkeylessApiClient akeylessApiClient) {
        this.akeylessApiClient = Objects.requireNonNull(akeylessApiClient, "akeylessApiClient");
    }

    @Override
    public byte[] sign(byte[] data, AkeylessCloudKeyInfo keyInfo, SignatureAlgorithm algorithm) {
        SignResponse res = akeylessApiClient.sign(keyInfo.getKeyName(), data);

        return Base64.getDecoder().decode(res.getResult());
    }

    @Override
    public boolean supports(PublicKey publicKey) {
        if (publicKey instanceof CloudPublicKey) {
            return ((CloudPublicKey<?, ?>) publicKey).getCloudKeyInfo().getClass() == AkeylessCloudKeyInfo.class;
        }

        return false;
    }
}
