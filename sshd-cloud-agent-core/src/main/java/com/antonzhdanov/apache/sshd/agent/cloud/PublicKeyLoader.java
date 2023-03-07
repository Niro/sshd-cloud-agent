package com.antonzhdanov.apache.sshd.agent.cloud;

import com.antonzhdanov.apache.sshd.agent.cloud.key.CloudPublicKey;

import java.security.PublicKey;

public interface PublicKeyLoader<K extends CloudKeyInfo> {
    CloudPublicKey<K, PublicKey> loadPublicKey(K keyInfo);
}
