package com.antonzhdanov.apache.sshd.agent.cloud;

import java.security.PublicKey;

public interface PublicKeyLoader<K extends CloudKeyInfo> {
    CloudPublicKey<K, ? extends PublicKey> loadPublicKey(K keyInfo);
}
