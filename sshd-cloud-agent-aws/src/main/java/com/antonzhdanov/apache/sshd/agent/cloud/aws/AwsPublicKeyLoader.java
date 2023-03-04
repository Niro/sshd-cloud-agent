package com.antonzhdanov.apache.sshd.agent.cloud.aws;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.PublicKeyLoader;
import com.antonzhdanov.apache.sshd.agent.cloud.PublicKeyUtils;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;

import java.security.PublicKey;
import java.util.concurrent.CompletableFuture;

import static java.util.Objects.requireNonNull;

public class AwsPublicKeyLoader implements PublicKeyLoader<AwsCloudKeyInfo> {

    private final KmsClient kmsClient;
    private final CloudPublicKeyFactory cloudPublicKeyFactory;

    public AwsPublicKeyLoader(KmsClient kmsClient, CloudPublicKeyFactory cloudPublicKeyFactory) {
        this.kmsClient = requireNonNull(kmsClient, "kmsClient");
        this.cloudPublicKeyFactory = requireNonNull(cloudPublicKeyFactory, "cloudPublicKeyFactory");
    }

    @Override
    public CloudPublicKey<AwsCloudKeyInfo, ? extends PublicKey> getPublicKey(AwsCloudKeyInfo keyInfo) {
        GetPublicKeyRequest request = GetPublicKeyRequest.builder().keyId(keyInfo.getKeyId()).build();
        GetPublicKeyResponse response = kmsClient.getPublicKey(request);

        PublicKey publicKey = PublicKeyUtils.parsePublicKey(response.publicKey().asByteArray());

        return cloudPublicKeyFactory.create(publicKey, keyInfo);
    }
}
