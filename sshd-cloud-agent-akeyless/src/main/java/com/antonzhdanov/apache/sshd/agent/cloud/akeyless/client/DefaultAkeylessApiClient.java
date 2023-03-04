package com.antonzhdanov.apache.sshd.agent.cloud.akeyless.client;

import com.antonzhdanov.apache.sshd.agent.cloud.akeyless.client.api.request.GetPublicKeyRequest;
import com.antonzhdanov.apache.sshd.agent.cloud.akeyless.client.api.request.SignRequest;
import com.antonzhdanov.apache.sshd.agent.cloud.akeyless.client.api.response.GetPublicKeyResponse;
import com.antonzhdanov.apache.sshd.agent.cloud.akeyless.client.api.response.SignResponse;
import com.google.gson.Gson;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;

public class DefaultAkeylessApiClient implements AkeylessApiClient {

    private final String token;
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final Gson gson = new Gson();

    public DefaultAkeylessApiClient(String token) {
        this.token = token;
    }

    @Override
    public GetPublicKeyResponse getPublicKey(String name) {
        GetPublicKeyRequest getPublicKeyRequest = GetPublicKeyRequest.builder()
                .token(token)
                .name(name)
                .build();

        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create("https://api.akeyless.io/get-rsa-public"))
                .header("accept", "application/json")
                .headers("content-type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(new Gson().toJson(getPublicKeyRequest)))
                .build();

        try {
            HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

            return gson.fromJson(response.body(), GetPublicKeyResponse.class);
        } catch (Exception exc) {
            throw new RuntimeException(exc);
        }
    }

    @Override
    public SignResponse sign(String name, byte[] message) {
        SignRequest signRequest = SignRequest.builder()
                .name(name)
                .token(token)
                .message(Base64.getEncoder().encodeToString(message))
                .build();

        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create("https://api.akeyless.io/sign-pkcs1"))
                .header("accept", "application/json")
                .headers("content-type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(new Gson().toJson(signRequest)))
                .build();

        try {
            HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

            return gson.fromJson(response.body(), SignResponse.class);
        } catch (Exception exc) {
            throw new RuntimeException(exc);
        }
    }
}
