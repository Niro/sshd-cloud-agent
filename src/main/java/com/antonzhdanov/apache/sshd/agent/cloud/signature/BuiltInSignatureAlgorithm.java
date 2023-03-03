package com.antonzhdanov.apache.sshd.agent.cloud.signature;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;

import static java.util.Objects.requireNonNull;

public enum BuiltInSignatureAlgorithm implements SignatureAlgorithm {
    RSA_SHA256(KeyUtils.RSA_SHA256_KEY_TYPE_ALIAS),
    RSA_SHA512(KeyUtils.RSA_SHA512_KEY_TYPE_ALIAS),
    ECDSA_SHA_256(KeyPairProvider.ECDSA_SHA2_NISTP256),
    ECDSA_SHA_384(KeyPairProvider.ECDSA_SHA2_NISTP384),
    ECDSA_SHA_512(KeyPairProvider.ECDSA_SHA2_NISTP521),
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
