package com.antonzhdanov.apache.sshd.agent.cloud;

import com.antonzhdanov.apache.sshd.agent.cloud.signature.Signature;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithm;

import java.security.PublicKey;

public interface Signer<K extends CloudKeyInfo> {
    Signature sign(byte[] data, K keyInfo, SignatureAlgorithm algorithm);

    boolean supports(PublicKey publicKey);
}
