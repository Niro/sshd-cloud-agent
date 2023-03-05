package com.antonzhdanov.apache.sshd.agent.cloud.azure;

import com.azure.security.keyvault.keys.cryptography.CryptographyClient;

@FunctionalInterface
public interface CryptographyClientProvider {
    CryptographyClient getClientForKey(AzureCloudKeyInfo keyInfo);
}
