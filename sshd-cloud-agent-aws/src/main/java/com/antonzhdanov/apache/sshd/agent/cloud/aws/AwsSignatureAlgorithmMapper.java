package com.antonzhdanov.apache.sshd.agent.cloud.aws;

import com.antonzhdanov.apache.sshd.agent.cloud.signature.BuiltInSignatureAlgorithm;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithm;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithmMapper;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class AwsSignatureAlgorithmMapper implements SignatureAlgorithmMapper<SigningAlgorithmSpec, SignatureAlgorithm> {

    private static final Map<SignatureAlgorithm, SigningAlgorithmSpec> SIGN_ALGO_AWS_MAPPING = new HashMap<>() {{
        put(BuiltInSignatureAlgorithm.RSA_SHA256, SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256);
        put(BuiltInSignatureAlgorithm.RSA_SHA512, SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512);
    }};

    @Override
    public Optional<SigningAlgorithmSpec> map(SignatureAlgorithm algorithm) {
        return Optional.ofNullable(SIGN_ALGO_AWS_MAPPING.get(algorithm));
    }
}
