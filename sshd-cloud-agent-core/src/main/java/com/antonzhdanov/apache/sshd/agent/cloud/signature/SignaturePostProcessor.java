package com.antonzhdanov.apache.sshd.agent.cloud.signature;

import java.security.PublicKey;

public interface SignaturePostProcessor {
    byte[] postProcessSignature(byte[] signature, PublicKey publicKey);
}
