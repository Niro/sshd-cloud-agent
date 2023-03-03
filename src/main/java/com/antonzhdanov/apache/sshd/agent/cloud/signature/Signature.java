package com.antonzhdanov.apache.sshd.agent.cloud.signature;

import static java.util.Objects.requireNonNull;

public class Signature {
    private final byte[] bytes;
    private final SignatureAlgorithm signatureAlgorithm;

    public Signature(byte[] bytes, SignatureAlgorithm signatureAlgorithm) {
        this.bytes = requireNonNull(bytes, "bytes");
        this.signatureAlgorithm = requireNonNull(signatureAlgorithm, "signatureAlgorithm");
    }

    public byte[] getBytes() {
        return bytes;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }
}
