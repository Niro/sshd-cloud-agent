package com.antonzhdanov.apache.sshd.agent.cloud.signature;

import static java.util.Objects.requireNonNull;

public enum BuiltInSignatureAlgorithm implements SignatureAlgorithm {
    RSA_PCKS1_V15_SHA256("rsa-sha2-256"),
    RSA_PCKS1_V15_SHA512("rsa-sha2-512"),
    ECDSA_SHA_256("ecdsa-sha2-nistp256"),
    ECDSA_SHA_384("ecdsa-sha2-nistp384"),
    ;

    private final String openSshFormat;

    BuiltInSignatureAlgorithm(String openSshFormat) {
        this.openSshFormat = requireNonNull(openSshFormat, "knownAlgorithm");
    }

    @Override
    public String toOpenSshFormat() {
        return openSshFormat;
    }

    public static SignatureAlgorithm fromKnownAlgorithm(String algo) {
        for (BuiltInSignatureAlgorithm signatureAlgorithm : BuiltInSignatureAlgorithm.values()) {
            if (signatureAlgorithm.toOpenSshFormat().equals(algo)) {
                return signatureAlgorithm;
            }
        }

        throw new UnsupportedOperationException(algo);
    }
}
