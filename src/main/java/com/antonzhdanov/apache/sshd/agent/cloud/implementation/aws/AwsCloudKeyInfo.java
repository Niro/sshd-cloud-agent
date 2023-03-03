package com.antonzhdanov.apache.sshd.agent.cloud.implementation.aws;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import lombok.Builder;
import lombok.Data;

import static java.util.Objects.requireNonNull;

@Data
@Builder
public class AwsCloudKeyInfo implements CloudKeyInfo {

    private final String keyId;

    public AwsCloudKeyInfo(String keyId) {
        this.keyId = requireNonNull(keyId, "keyId");
    }

    @Override
    public String getComment() {
        return "AWS " + keyId;
    }
}
