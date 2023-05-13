package com.antonzhdanov.apache.sshd.agent.cloud.oracle;

import com.antonzhdanov.apache.sshd.agent.cloud.PublicKeyLoader;
import com.antonzhdanov.apache.sshd.agent.cloud.key.CloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.key.CloudPublicKeyFactory;
import com.oracle.bmc.keymanagement.KmsManagement;
import com.oracle.bmc.keymanagement.requests.GetKeyVersionRequest;
import com.oracle.bmc.keymanagement.responses.GetKeyVersionResponse;

import java.security.PublicKey;

public class OraclePublicKeyLoader implements PublicKeyLoader<OracleCloudKeyInfo> {

    private final KmsManagement kmsManagement;
    private final CloudPublicKeyFactory<OracleCloudKeyInfo> publicKeyFactory;

    public OraclePublicKeyLoader(KmsManagement kmsManagement, CloudPublicKeyFactory<OracleCloudKeyInfo> publicKeyFactory) {
        this.kmsManagement = kmsManagement;
        this.publicKeyFactory = publicKeyFactory;
    }

    @Override
    public CloudPublicKey<OracleCloudKeyInfo, PublicKey> loadPublicKey(OracleCloudKeyInfo keyInfo) {
        GetKeyVersionRequest getKeyVersionRequest = GetKeyVersionRequest.builder()
                .keyId(keyInfo.getKeyId())
                .keyVersionId(keyInfo.getKeyVersionId())
                .build();
        GetKeyVersionResponse key = kmsManagement.getKeyVersion(getKeyVersionRequest);

        String publicKeyPem = key.getKeyVersion().getPublicKey();

        return publicKeyFactory.create(publicKeyPem, keyInfo);
    }
}
