package com.antonzhdanov.apache.sshd.agent.cloud.aws;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.PublicKeyLoader;
import com.antonzhdanov.apache.sshd.agent.cloud.PublicKeyUtils;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;

import java.security.PublicKey;
import java.util.concurrent.CompletableFuture;

import static java.util.Objects.requireNonNull;

public class AwsPublicKeyLoader implements PublicKeyLoader<AwsCloudKeyInfo> {

    private final KmsAsyncClient kmsAsyncClient;
    private final CloudPublicKeyFactory cloudPublicKeyFactory;

    public AwsPublicKeyLoader(KmsAsyncClient kmsAsyncClient, CloudPublicKeyFactory cloudPublicKeyFactory) {
        this.kmsAsyncClient = requireNonNull(kmsAsyncClient, "kmsAsyncClient");
        this.cloudPublicKeyFactory = requireNonNull(cloudPublicKeyFactory, "cloudPublicKeyFactory");
    }

    @Override
    public CompletableFuture<CloudPublicKey<AwsCloudKeyInfo, ? extends PublicKey>> getPublicKey(AwsCloudKeyInfo keyInfo) {
        return kmsAsyncClient.getPublicKey(GetPublicKeyRequest.builder().keyId(keyInfo.getKeyId()).build())
                .thenApply(response -> processResponse(response, keyInfo));
    }

    private CloudPublicKey<AwsCloudKeyInfo, ? extends PublicKey> processResponse(GetPublicKeyResponse response, AwsCloudKeyInfo keyInfo) {
        PublicKey publicKey = PublicKeyUtils.parsePublicKey(response.publicKey().asByteArray());
        return cloudPublicKeyFactory.create(publicKey, keyInfo);
    }
}
