package com.antonzhdanov.apache.sshd.agent.cloud;

import java.util.Objects;

public abstract class AbstractCloudKeyInfo implements CloudKeyInfo {
    private final String keyId;

    public AbstractCloudKeyInfo(String keyId) {
        this.keyId = Objects.requireNonNull(keyId, "keyId");
    }

    @Override
    public String getKeyId() {
        return keyId;
    }

    @Override
    public String getComment() {
        return getCloudProvider().getName() + " " + getKeyId();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }

        AbstractCloudKeyInfo that = (AbstractCloudKeyInfo) obj;
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
