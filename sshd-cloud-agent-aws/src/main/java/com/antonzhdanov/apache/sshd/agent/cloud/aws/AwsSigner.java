package com.antonzhdanov.apache.sshd.agent.cloud.aws;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithm;
import com.antonzhdanov.apache.sshd.agent.cloud.Signer;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.SignRequest;

import java.security.PublicKey;

import static java.util.Objects.requireNonNull;

public class AwsSigner implements Signer<AwsCloudKeyInfo> {

    private final KmsClient kmsClient;
    private final AwsSignatureAlgorithmMapper signatureAlgorithmMapper;

    public AwsSigner(KmsClient kmsClient, AwsSignatureAlgorithmMapper signatureAlgorithmMapper) {
        this.kmsClient = requireNonNull(kmsClient, "kmsClient");
        this.signatureAlgorithmMapper = requireNonNull(signatureAlgorithmMapper, "signatureAlgorithmMapper");
    }

    @Override
    public byte[] sign(byte[] data, AwsCloudKeyInfo keyInfo, SignatureAlgorithm algorithm) {
        SignRequest request = SignRequest.builder()
                .keyId(keyInfo.getKeyId())
                .signingAlgorithm(signatureAlgorithmMapper.map(algorithm).orElseThrow(NullPointerException::new))
                .message(SdkBytes.fromByteArray(data))
                .build();

        return kmsClient.sign(request).signature().asByteArray();
    }

    @Override
    public boolean supports(PublicKey publicKey) {
        if (publicKey instanceof CloudPublicKey) {
            return ((CloudPublicKey<?, ?>) publicKey).getCloudKeyInfo().getClass() == AwsCloudKeyInfo.class;
        }

        return false;
    }
}
