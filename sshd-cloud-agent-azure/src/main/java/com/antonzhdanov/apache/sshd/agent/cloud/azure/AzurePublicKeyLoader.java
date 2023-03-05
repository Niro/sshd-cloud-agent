package com.antonzhdanov.apache.sshd.agent.cloud.azure;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.PublicKeyLoader;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.models.JsonWebKey;
import com.azure.security.keyvault.keys.models.KeyCurveName;
import com.azure.security.keyvault.keys.models.KeyType;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import org.apache.sshd.common.cipher.ECCurves;

import java.math.BigInteger;
import java.security.PublicKey;

import static java.util.Objects.requireNonNull;

public class AzurePublicKeyLoader implements PublicKeyLoader<AzureCloudKeyInfo> {

    private final CryptographyClientProvider cryptographyClientProvider;
    private final CloudPublicKeyFactory<AzureCloudKeyInfo> cloudPublicKeyFactory;

    public AzurePublicKeyLoader(CryptographyClientProvider cryptographyClientProvider,
                                CloudPublicKeyFactory<AzureCloudKeyInfo> cloudPublicKeyFactory) {
        this.cryptographyClientProvider = requireNonNull(cryptographyClientProvider, "cryptographyClientProvider");
        this.cloudPublicKeyFactory = requireNonNull(cloudPublicKeyFactory, "cloudPublicKeyFactory");
    }

    @Override
    public CloudPublicKey<AzureCloudKeyInfo, ? extends PublicKey> loadPublicKey(AzureCloudKeyInfo keyInfo) {
        CryptographyClient client = cryptographyClientProvider.getClientForKey(keyInfo);

        requireNonNull(client, cryptographyClientProvider.getClass().getName() + " didn't provide instance of " + CryptographyClient.class.getName());

        KeyVaultKey key = client.getKey();

        if (KeyType.RSA.equals(key.getKeyType())) {
            return mapRsaKey(key.getKey(), keyInfo);
        } else if (KeyType.EC.equals(key.getKeyType())) {
            return mapEcKey(key.getKey(), keyInfo);
        } else {
            throw new UnsupportedOperationException(key.getKeyType().toString());
        }
    }

    private CloudPublicKey<AzureCloudKeyInfo, ? extends PublicKey> mapRsaKey(JsonWebKey jsonWebKey, AzureCloudKeyInfo keyInfo) {
        BigInteger modulus = new BigInteger(1, jsonWebKey.getN());
        BigInteger publicExponent = new BigInteger(jsonWebKey.getE());

        return cloudPublicKeyFactory.create(modulus, publicExponent, keyInfo);
    }

    private CloudPublicKey<AzureCloudKeyInfo, ? extends PublicKey> mapEcKey(JsonWebKey jsonWebKey, AzureCloudKeyInfo keyInfo) {
        BigInteger x = new BigInteger(1, jsonWebKey.getX());
        BigInteger y = new BigInteger(1, jsonWebKey.getY());
        ECCurves ecCurve;

        KeyCurveName curveName = jsonWebKey.getCurveName();
        if (curveName.equals(KeyCurveName.P_256)) {
            ecCurve = ECCurves.nistp256;
        } else if (curveName.equals(KeyCurveName.P_384)) {
            ecCurve = ECCurves.nistp384;
        } else if (curveName.equals(KeyCurveName.P_521)) {
            ecCurve = ECCurves.nistp521;
        } else {
            throw new UnsupportedOperationException(curveName.toString());
        }

        return cloudPublicKeyFactory.create(x, y, ecCurve, keyInfo);
    }
}
