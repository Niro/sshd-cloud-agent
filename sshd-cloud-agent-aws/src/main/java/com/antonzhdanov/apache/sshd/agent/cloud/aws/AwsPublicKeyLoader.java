package com.antonzhdanov.apache.sshd.agent.cloud.aws;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.key.CloudPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.PublicKeyLoader;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;

import java.security.PublicKey;

import static java.util.Objects.requireNonNull;

public class AwsPublicKeyLoader implements PublicKeyLoader<AwsCloudKeyInfo> {

    private final KmsClient kmsClient;
    private final CloudPublicKeyFactory<AwsCloudKeyInfo> cloudPublicKeyFactory;

    public AwsPublicKeyLoader(KmsClient kmsClient, CloudPublicKeyFactory<AwsCloudKeyInfo> cloudPublicKeyFactory) {
        this.kmsClient = requireNonNull(kmsClient, "kmsClient");
        this.cloudPublicKeyFactory = requireNonNull(cloudPublicKeyFactory, "cloudPublicKeyFactory");
    }

    @Override
    public CloudPublicKey<AwsCloudKeyInfo, ? extends PublicKey> loadPublicKey(AwsCloudKeyInfo keyInfo) {
        GetPublicKeyRequest request = GetPublicKeyRequest.builder().keyId(keyInfo.getKeyId()).build();
        GetPublicKeyResponse response = kmsClient.getPublicKey(request);

        return cloudPublicKeyFactory.create(response.publicKey().asByteArray(), keyInfo);
    }
}
