package com.antonzhdanov.apache.sshd.agent.cloud.signature;

import java.util.Optional;

public class SshdSignatureAlgorithmMapper implements SignatureAlgorithmMapper<SignatureAlgorithm, String> {
    @Override
    public Optional<SignatureAlgorithm> map(String algorithm) {
        return Optional.of(BuiltInSignatureAlgorithm.fromKnownAlgorithm(algorithm));
    }
}
