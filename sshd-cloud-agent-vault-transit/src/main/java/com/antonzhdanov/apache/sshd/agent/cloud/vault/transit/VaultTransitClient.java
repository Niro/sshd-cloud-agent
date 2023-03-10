package com.antonzhdanov.apache.sshd.agent.cloud.vault.transit;

/**
 * Vault has no official SDK. Vault Transit users must provide access for certain API:
 * <ul>
 *     <li><a href="https://developer.hashicorp.com/vault/api-docs/secret/transit#read-key">Read Key</a>
 *     <li><a href="https://developer.hashicorp.com/vault/api-docs/secret/transit#sign-data">Sign Data</a>
 * </ul>
 *
 * Client is responsible only for access to API and sending request.
 */
public interface VaultTransitClient {
    /**
     * Used for reading public key. Response is handled by lib. You can handle error by yourself.
     * But in this case you might throw and exception.
     *
     * @param path endpoint to query by template /v1/transit/keys/%KEY_ID%. Concat Vault address with this
     * @return must return response JSON as is
     */
    String readKey(String path);

    /**
     * Used for signing data. Response is handled by lib. You can handle error by yourself.
     * But in this case you might throw and exception.
     *
     * @param path endpoint to query by template /v1/transit/sign/%KEY_ID%/%ALGORITHM%. Concat Vault address with this
     * @param body Request body
     * @return must return response JSON as is
     */
    String signData(String path, String body);
}
