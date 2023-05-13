package com.antonzhdanov.apache.sshd.agent.cloud.oracle;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudProvider;

public class OracleCloudProvider implements CloudProvider {
    public static final OracleCloudProvider INSTANCE = new OracleCloudProvider();

    private OracleCloudProvider() {

    }

    @Override
    public String getName() {
        return "Oracle";
    }
}
