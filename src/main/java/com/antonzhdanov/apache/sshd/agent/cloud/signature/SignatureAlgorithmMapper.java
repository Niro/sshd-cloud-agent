package com.antonzhdanov.apache.sshd.agent.cloud.signature;

import java.util.Optional;

public interface SignatureAlgorithmMapper<S, D> {
    Optional<S> map(D algorithm);
}
