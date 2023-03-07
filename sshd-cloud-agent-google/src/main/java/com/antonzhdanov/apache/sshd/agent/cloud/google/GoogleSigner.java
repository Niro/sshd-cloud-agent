package com.antonzhdanov.apache.sshd.agent.cloud.google;

import com.antonzhdanov.apache.sshd.agent.cloud.AbstractSigner;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithm;
import com.google.cloud.kms.v1.AsymmetricSignRequest;
import com.google.cloud.kms.v1.AsymmetricSignResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.protobuf.ByteString;

import static java.util.Objects.requireNonNull;

public class GoogleSigner extends AbstractSigner<GoogleCloudKeyInfo> {

    private final KeyManagementServiceClient keyManagementServiceClient;

    public GoogleSigner(KeyManagementServiceClient keyManagementServiceClient) {
        super(GoogleCloudKeyInfo.class);
        this.keyManagementServiceClient = requireNonNull(keyManagementServiceClient, "keyManagementServiceClient");
    }

    @Override
    public byte[] sign(byte[] data, GoogleCloudKeyInfo keyInfo, SignatureAlgorithm algorithm) {
        AsymmetricSignResponse asymmetricSignResponse = keyManagementServiceClient.asymmetricSign(AsymmetricSignRequest.newBuilder()
                .setData(ByteString.copyFrom(data))
                .setName(keyInfo.toCryptoKeyVersionName().toString())
                .build());

        return asymmetricSignResponse.getSignature().toByteArray();
    }
}
