package com.antonzhdanov.apache.sshd.agent.cloud.google;

import com.antonzhdanov.apache.sshd.agent.cloud.PublicKeyLoader;
import com.antonzhdanov.apache.sshd.agent.cloud.key.CloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.key.CloudPublicKeyFactory;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.PublicKey;

import static java.util.Objects.requireNonNull;

public class GooglePublicKeyLoader implements PublicKeyLoader<GoogleCloudKeyInfo> {

    private final KeyManagementServiceClient keyManagementServiceClient;
    private final CloudPublicKeyFactory<GoogleCloudKeyInfo> cloudPublicKeyFactory;

    public GooglePublicKeyLoader(KeyManagementServiceClient keyManagementServiceClient,
                                 CloudPublicKeyFactory<GoogleCloudKeyInfo> cloudPublicKeyFactory) {
        this.keyManagementServiceClient = requireNonNull(keyManagementServiceClient, "keyManagementServiceClient");
        this.cloudPublicKeyFactory = requireNonNull(cloudPublicKeyFactory, "cloudPublicKeyFactory");
    }

    @Override
    public CloudPublicKey<GoogleCloudKeyInfo, java.security.PublicKey> loadPublicKey(GoogleCloudKeyInfo keyInfo) {
        PublicKey response = keyManagementServiceClient.getPublicKey(keyInfo.toCryptoKeyVersionName());
        return cloudPublicKeyFactory.create(response.getPem(), keyInfo);
    }
}
