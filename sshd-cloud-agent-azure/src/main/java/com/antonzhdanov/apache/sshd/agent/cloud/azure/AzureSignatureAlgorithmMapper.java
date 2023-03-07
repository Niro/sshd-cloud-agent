package com.antonzhdanov.apache.sshd.agent.cloud.azure;

import com.antonzhdanov.apache.sshd.agent.cloud.signature.BuiltInSignatureAlgorithm;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithm;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithmMapper;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm.ES256;
import static com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm.ES384;
import static com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm.ES512;
import static com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm.RS256;
import static com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm.RS384;
import static com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm.RS512;

public class AzureSignatureAlgorithmMapper implements SignatureAlgorithmMapper<com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm, SignatureAlgorithm> {

    private static final Map<SignatureAlgorithm, com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm> SIGN_ALGO_AWS_MAPPING = new HashMap<>() {{
        put(BuiltInSignatureAlgorithm.RSA_PCKS1_V15_SHA256, RS256);
        put(BuiltInSignatureAlgorithm.RSA_PCKS1_V15_SHA384, RS384);
        put(BuiltInSignatureAlgorithm.RSA_PCKS1_V15_SHA512, RS512);
        put(BuiltInSignatureAlgorithm.ECDSA_SHA_256, ES256);
        put(BuiltInSignatureAlgorithm.ECDSA_SHA_384, ES384);
        put(BuiltInSignatureAlgorithm.ECDSA_SHA_512, ES512);
    }};

    @Override
    public Optional<com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm> map(SignatureAlgorithm algorithm) {
        return Optional.ofNullable(SIGN_ALGO_AWS_MAPPING.get(algorithm));
    }
}
