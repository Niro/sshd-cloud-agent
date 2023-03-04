package com.antonzhdanov.apache.sshd.agent.cloud.akeyless.client.api.request;

import com.google.gson.annotations.SerializedName;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SignRequest {
    @SerializedName("key-name")
    private String name;

    private String token;

    private String message;
}
