package com.antonzhdanov.apache.sshd.agent.cloud.akeyless.client;

import com.antonzhdanov.apache.sshd.agent.cloud.akeyless.client.api.response.GetPublicKeyResponse;
import com.antonzhdanov.apache.sshd.agent.cloud.akeyless.client.api.response.SignResponse;

public interface AkeylessApiClient {
    GetPublicKeyResponse getPublicKey(String name);

    SignResponse sign(String name, byte[] message);
}
