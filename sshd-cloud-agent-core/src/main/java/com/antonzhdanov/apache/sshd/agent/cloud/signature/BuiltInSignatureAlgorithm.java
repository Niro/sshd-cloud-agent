package com.antonzhdanov.apache.sshd.agent.cloud.signature;

import static java.util.Objects.requireNonNull;

public enum BuiltInSignatureAlgorithm implements SignatureAlgorithm {
    RSA_SHA256("rsa-sha2-256"),
    RSA_SHA512("rsa-sha2-512"),
    ;

    private final String knownAlgorithm;

    BuiltInSignatureAlgorithm(String knownAlgorithm) {
        this.knownAlgorithm = requireNonNull(knownAlgorithm, "knownAlgorithm");
    }

    @Override
    public String toKnownAlgorithm() {
        return knownAlgorithm;
    }

    public static SignatureAlgorithm fromKnownAlgorithm(String algo) {
        for (BuiltInSignatureAlgorithm signatureAlgorithm : BuiltInSignatureAlgorithm.values()) {
            if (signatureAlgorithm.toKnownAlgorithm().equals(algo)) {
                return signatureAlgorithm;
            }
        }

        throw new UnsupportedOperationException(algo);
    }
}
