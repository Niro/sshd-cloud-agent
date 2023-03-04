package com.antonzhdanov.apache.sshd.agent.cloud.akeyless;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.PublicKeyLoader;
import com.antonzhdanov.apache.sshd.agent.cloud.PublicKeyUtils;
import com.antonzhdanov.apache.sshd.agent.cloud.akeyless.client.AkeylessApiClient;
import com.antonzhdanov.apache.sshd.agent.cloud.akeyless.client.api.response.GetPublicKeyResponse;

import java.security.PublicKey;

import static java.util.Objects.requireNonNull;

public class AkeylessPublicKeyLoader implements PublicKeyLoader<AkeylessCloudKeyInfo> {

    private final AkeylessApiClient akeylessApiClient;
    private final CloudPublicKeyFactory cloudPublicKeyFactory;

    public AkeylessPublicKeyLoader(AkeylessApiClient akeylessApiClient,
                                   CloudPublicKeyFactory cloudPublicKeyFactory) {
        this.akeylessApiClient = requireNonNull(akeylessApiClient, "akeylessApiClient");
        this.cloudPublicKeyFactory = requireNonNull(cloudPublicKeyFactory, "cloudPublicKeyFactory");
    }

    @Override
    public CloudPublicKey<AkeylessCloudKeyInfo, ? extends PublicKey> loadPublicKey(AkeylessCloudKeyInfo keyInfo) {
        GetPublicKeyResponse response = akeylessApiClient.getPublicKey(keyInfo.getKeyName());

        return cloudPublicKeyFactory.create(PublicKeyUtils.fromPem(response.getPem()), keyInfo);
    }
}
