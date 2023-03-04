package com.antonzhdanov.apache.sshd.agent.cloud.akeyless.client.api.response;

import lombok.Data;

@Data
public class GetPublicKeyResponse {
    private String pem;
    private String raw;
    private String ssh;
}
