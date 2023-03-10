package com.antonzhdanov.apache.sshd.agent.cloud.vault.transit;

import com.antonzhdanov.apache.sshd.agent.cloud.signature.BuiltInSignatureAlgorithm;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithm;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithmMapper;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class VaultTransitSignatureAlgorithmMapper implements SignatureAlgorithmMapper<String, SignatureAlgorithm> {

    private static final Map<SignatureAlgorithm, String> VAULT_ALGOS = new HashMap<>() {{
        put(BuiltInSignatureAlgorithm.RSA_PCKS1_V15_SHA256, "sha2-256");
        put(BuiltInSignatureAlgorithm.RSA_PCKS1_V15_SHA384, "sha2-384");
        put(BuiltInSignatureAlgorithm.RSA_PCKS1_V15_SHA512, "sha2-512");
        put(BuiltInSignatureAlgorithm.ECDSA_SHA_256, "sha2-256");
        put(BuiltInSignatureAlgorithm.ECDSA_SHA_384, "sha2-384");
        put(BuiltInSignatureAlgorithm.ECDSA_SHA_512, "sha2-512");
    }};

    @Override
    public Optional<String> map(SignatureAlgorithm algorithm) {
        return Optional.ofNullable(VAULT_ALGOS.get(algorithm));
    }
}
