package com.antonzhdanov.apache.sshd.agent.cloud.azure;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.Signer;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithm;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;

import java.security.PublicKey;

import static java.util.Objects.requireNonNull;

public class AzureSigner implements Signer<AzureCloudKeyInfo> {

    private final CryptographyClientProvider cryptographyClientProvider;
    private final AzureSignatureAlgorithmMapper signatureAlgorithmMapper;

    public AzureSigner(CryptographyClientProvider cryptographyClientProvider,
                       AzureSignatureAlgorithmMapper signatureAlgorithmMapper) {
        this.cryptographyClientProvider = requireNonNull(cryptographyClientProvider, "cryptographyClientProvider");
        this.signatureAlgorithmMapper = requireNonNull(signatureAlgorithmMapper, "signatureAlgorithmMapper");
    }

    @Override
    public byte[] sign(byte[] data, AzureCloudKeyInfo keyInfo, SignatureAlgorithm algorithm) {
        CryptographyClient client = cryptographyClientProvider.getClientForKey(keyInfo);

        SignResult signResult = client.signData(signatureAlgorithmMapper.map(algorithm).orElseThrow(), data);

        return signResult.getSignature();
    }

    @Override
    public boolean supports(PublicKey publicKey) {
        if (publicKey instanceof CloudPublicKey) {
            return ((CloudPublicKey<?, ?>) publicKey).getCloudKeyInfo().getClass() == AzureCloudKeyInfo.class;
        }

        return false;
    }
}
