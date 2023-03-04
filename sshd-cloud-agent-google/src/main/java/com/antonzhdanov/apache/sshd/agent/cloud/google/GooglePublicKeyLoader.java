package com.antonzhdanov.apache.sshd.agent.cloud.google;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.PublicKeyLoader;
import com.antonzhdanov.apache.sshd.agent.cloud.PublicKeyUtils;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.PublicKey;

import java.util.concurrent.CompletableFuture;

import static java.util.Objects.requireNonNull;

public class GooglePublicKeyLoader implements PublicKeyLoader<GoogleCloudKeyInfo> {

    private final KeyManagementServiceClient keyManagementServiceClient;
    private final CloudPublicKeyFactory cloudPublicKeyFactory;

    public GooglePublicKeyLoader(KeyManagementServiceClient keyManagementServiceClient, CloudPublicKeyFactory cloudPublicKeyFactory) {
        this.keyManagementServiceClient = requireNonNull(keyManagementServiceClient, "keyManagementServiceClient");
        this.cloudPublicKeyFactory = requireNonNull(cloudPublicKeyFactory, "cloudPublicKeyFactory");
    }

    @Override
    public CloudPublicKey<GoogleCloudKeyInfo, ? extends java.security.PublicKey> getPublicKey(GoogleCloudKeyInfo keyInfo) {
        PublicKey response = keyManagementServiceClient.getPublicKey(keyInfo.toCryptoKeyVersionName());

        java.security.PublicKey publicKey = PublicKeyUtils.fromPem(response.getPem());

        return cloudPublicKeyFactory.create(publicKey, keyInfo);
    }
}
