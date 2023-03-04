package com.antonzhdanov.apache.sshd.agent.cloud.akeyless;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AkeylessCloudKeyInfo implements CloudKeyInfo {
    private final String keyName;

    public AkeylessCloudKeyInfo(String keyName) {
        this.keyName = keyName;
    }

    @Override
    public String getComment() {
        return "Akeyless " + keyName;
    }
}
