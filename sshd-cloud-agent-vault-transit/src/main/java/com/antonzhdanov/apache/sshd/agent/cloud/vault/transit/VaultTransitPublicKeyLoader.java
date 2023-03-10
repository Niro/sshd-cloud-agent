package com.antonzhdanov.apache.sshd.agent.cloud.vault.transit;

import com.antonzhdanov.apache.sshd.agent.cloud.PublicKeyLoader;
import com.antonzhdanov.apache.sshd.agent.cloud.key.CloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.key.CloudPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.vault.transit.exception.VaultTransitCloudSshAgentException;
import com.jayway.jsonpath.JsonPath;

import java.security.PublicKey;

import static java.util.Objects.requireNonNull;

public class VaultTransitPublicKeyLoader implements PublicKeyLoader<VaultTransitCloudKeyInfo> {

    private static final String VAULT_TRANSIT_GET_KEY_PATH_TEMPLATE = "/v1/transit/keys/%s";

    private final VaultTransitClient vaultTransitClient;
    private final CloudPublicKeyFactory<VaultTransitCloudKeyInfo> cloudPublicKeyFactory;

    public VaultTransitPublicKeyLoader(VaultTransitClient vaultTransitClient,
                                       CloudPublicKeyFactory<VaultTransitCloudKeyInfo> cloudPublicKeyFactory) {
        this.vaultTransitClient = requireNonNull(vaultTransitClient, "vaultTransitClient");
        this.cloudPublicKeyFactory = requireNonNull(cloudPublicKeyFactory, "cloudPublicKeyFactory");
    }

    @Override
    public CloudPublicKey<VaultTransitCloudKeyInfo, PublicKey> loadPublicKey(VaultTransitCloudKeyInfo keyInfo) {
        try {
            String responseBody = vaultTransitClient.readKey(String.format(VAULT_TRANSIT_GET_KEY_PATH_TEMPLATE,
                    keyInfo.getKeyId()));

            String pem = JsonPath.read(responseBody, "$.data.keys['1'].public_key");

            return cloudPublicKeyFactory.create(pem, keyInfo);
        } catch (Exception exc) {
            throw new VaultTransitCloudSshAgentException("Unable to obtain public key for " + keyInfo.getComment(), exc);
        }
    }
}
