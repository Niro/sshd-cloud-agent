package com.antonzhdanov.apache.sshd.agent.cloud.aws;

import com.antonzhdanov.apache.sshd.agent.cloud.AbstractSigner;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithm;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.SignRequest;

import static java.util.Objects.requireNonNull;

public class AwsSigner extends AbstractSigner<AwsCloudKeyInfo> {

    private final KmsClient kmsClient;
    private final AwsSignatureAlgorithmMapper signatureAlgorithmMapper;

    public AwsSigner(KmsClient kmsClient, AwsSignatureAlgorithmMapper signatureAlgorithmMapper) {
        super(AwsCloudKeyInfo.class);
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
}
