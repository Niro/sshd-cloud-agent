package com.antonzhdanov.apache.sshd.agent.cloud.yandex;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.PublicKeyLoader;

import java.security.PublicKey;

public class YandexPublicKeyLoader implements PublicKeyLoader<YandexCloudKeyInfo> {

    @Override
    public CloudPublicKey<YandexCloudKeyInfo, ? extends PublicKey> loadPublicKey(YandexCloudKeyInfo keyInfo) {
        return null;
    }
}
