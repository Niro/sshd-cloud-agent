package com.antonzhdanov.apache.sshd.agent.cloud.implementation.aws;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.Signature;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithm;
import com.antonzhdanov.apache.sshd.agent.cloud.Signer;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;

import java.security.PublicKey;

import static java.util.Objects.requireNonNull;

public class AwsSigner implements Signer<AwsCloudKeyInfo> {

    private final KmsAsyncClient kmsAsyncClient;
    private final AwsSignatureAlgorithmMapper signatureAlgorithmMapper;

    public AwsSigner(KmsAsyncClient kmsAsyncClient, AwsSignatureAlgorithmMapper signatureAlgorithmMapper) {
        this.kmsAsyncClient = requireNonNull(kmsAsyncClient, "kmsAsyncClient");
        this.signatureAlgorithmMapper = requireNonNull(signatureAlgorithmMapper, "signatureAlgorithmMapper");
    }

    @Override
    public Signature sign(byte[] data, AwsCloudKeyInfo keyInfo, SignatureAlgorithm algorithm) {
        SignRequest request = SignRequest.builder()
                .keyId(keyInfo.getKeyId())
                .signingAlgorithm(signatureAlgorithmMapper.map(algorithm).orElseThrow(NullPointerException::new))
                .message(SdkBytes.fromByteArray(data))
                .build();

        SignResponse signResponse = kmsAsyncClient.sign(request).join();

        return new Signature(signResponse.signature().asByteArray(), algorithm);
    }

    @Override
    public boolean supports(PublicKey publicKey) {
        if (publicKey instanceof CloudPublicKey) {
            return ((CloudPublicKey<?, ?>) publicKey).getCloudKeyInfo().getClass() == AwsCloudKeyInfo.class;
        }

        return false;
    }
}
