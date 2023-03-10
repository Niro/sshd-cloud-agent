package com.antonzhdanov.apache.sshd.agent.cloud.vault.transit;

import com.antonzhdanov.apache.sshd.agent.cloud.key.JcaPublicKeyFactory;
import com.jayway.jsonpath.JsonPath;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;

import static java.util.Objects.requireNonNull;

public class TestVaultTransitClient implements VaultTransitClient {

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final String token;
    private final String url;

    public TestVaultTransitClient(String token, String url) {
        this.token = requireNonNull(token, "token");
        this.url = requireNonNull(url, "url");
    }

    @Override
    public String readKey(String path) {
        HttpRequest request = HttpRequest.newBuilder()
                .header("X-Vault-Token", token)
                .uri(URI.create(url + path))
                .GET()
                .build();

        try {
            return httpClient.send(request, HttpResponse.BodyHandlers.ofString()).body();
        } catch (Exception exc) {
            throw new RuntimeException(exc);
        }
    }

    @Override
    public String signData(String path, String body) {
        HttpRequest request = HttpRequest.newBuilder()
                .header("X-Vault-Token", token)
                .uri(URI.create(url + path))
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        try {
            return httpClient.send(request, HttpResponse.BodyHandlers.ofString()).body();
        } catch (Exception exc) {
            throw new RuntimeException(exc);
        }
    }

    public PublicKey createKey(String type) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .header("X-Vault-Token", token)
                    .uri(URI.create(url + "/v1/transit/keys/" + type))
                    .POST(HttpRequest.BodyPublishers.ofString("{\"type\": \"" + type + "\"}"))
                    .build();

            httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            request = HttpRequest.newBuilder()
                    .header("X-Vault-Token", token)
                    .uri(URI.create(url + "/v1/transit/keys/" + type))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            String pem = JsonPath.read(response.body(), "$.data.keys['1'].public_key");
            return new JcaPublicKeyFactory().create(pem);
        } catch (Exception exc) {
            throw new RuntimeException(exc);
        }
    }
}
