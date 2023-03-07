package com.antonzhdanov.apache.sshd.agent.cloud.aws;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudProvider;

import java.util.Objects;

import static java.util.Objects.requireNonNull;

public class AwsCloudKeyInfo implements CloudKeyInfo {

    private final String keyId;

    public AwsCloudKeyInfo(String keyId) {
        this.keyId = requireNonNull(keyId, "keyId");
    }

    @Override
    public String getComment() {
        return "AWS " + keyId;
    }

    public String getKeyId() {
        return keyId;
    }

    @Override
    public CloudProvider getCloudProvider() {
        return AwsCloudProvider.INSTANCE;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }

        AwsCloudKeyInfo that = (AwsCloudKeyInfo) obj;
        return keyId.equals(that.keyId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyId);
    }

    @Override
    public String toString() {
        return getComment();
    }
}
