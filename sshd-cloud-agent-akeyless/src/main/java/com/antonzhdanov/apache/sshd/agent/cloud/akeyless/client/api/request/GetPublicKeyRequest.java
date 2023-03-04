package com.antonzhdanov.apache.sshd.agent.cloud.akeyless.client.api.request;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class GetPublicKeyRequest {
    private String token;

    private String name;
}
