package com.antonzhdanov.apache.sshd.agent.cloud.yandex;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;

import static java.util.Objects.requireNonNull;

public class YandexCloudKeyInfo implements CloudKeyInfo {

    private final String keyId;

    public YandexCloudKeyInfo(String keyId) {
        this.keyId = requireNonNull(keyId, "keyId");
    }

    @Override
    public String getComment() {
        return "Yandex " + keyId;
    }
}
