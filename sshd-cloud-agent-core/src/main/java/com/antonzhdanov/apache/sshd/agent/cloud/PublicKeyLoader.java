package com.antonzhdanov.apache.sshd.agent.cloud;

import java.security.PublicKey;
import java.util.concurrent.CompletableFuture;

public interface PublicKeyLoader<K extends CloudKeyInfo> {
    CompletableFuture<CloudPublicKey<K, ? extends PublicKey>> getPublicKey(K keyInfo);
}
