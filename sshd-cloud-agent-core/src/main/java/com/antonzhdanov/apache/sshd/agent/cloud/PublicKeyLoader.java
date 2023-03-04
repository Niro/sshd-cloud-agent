package com.antonzhdanov.apache.sshd.agent.cloud;

import java.security.PublicKey;
import java.util.concurrent.CompletableFuture;

public interface PublicKeyLoader<K extends CloudKeyInfo> {
    CloudPublicKey<K, ? extends PublicKey> getPublicKey(K keyInfo);
}
