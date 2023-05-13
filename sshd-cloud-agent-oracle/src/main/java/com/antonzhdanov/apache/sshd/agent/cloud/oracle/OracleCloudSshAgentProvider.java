package com.antonzhdanov.apache.sshd.agent.cloud.oracle;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgent;
import com.antonzhdanov.apache.sshd.agent.CloudSshAgentProvider;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudProvider;
import com.antonzhdanov.apache.sshd.agent.cloud.key.CloudPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.key.JcaPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.DefaultSignaturePostProcessor;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SshdSignatureAlgorithmMapper;
import com.oracle.bmc.keymanagement.KmsCrypto;
import com.oracle.bmc.keymanagement.KmsManagement;
import org.apache.sshd.common.session.Session;

public class OracleCloudSshAgentProvider implements CloudSshAgentProvider<OracleCloudKeyInfo> {

    private final KmsManagement kmsManagement;
    private final KmsCrypto kmsCrypto;

    public OracleCloudSshAgentProvider(KmsManagement kmsManagement, KmsCrypto kmsCrypto) {
        this.kmsManagement = kmsManagement;
        this.kmsCrypto = kmsCrypto;
    }

    @Override
    public CloudSshAgent<OracleCloudKeyInfo> create(Session session, OracleCloudKeyInfo keyInfo) {
        return new CloudSshAgent<>(new OracleSigner(kmsCrypto, new OracleSignatureAlgorithmMapper()),
                new OraclePublicKeyLoader(kmsManagement, new CloudPublicKeyFactory<>(new JcaPublicKeyFactory())),
                new DefaultSignaturePostProcessor(),
                keyInfo,
                new SshdSignatureAlgorithmMapper());
    }

    @Override
    public CloudProvider getCloudProvider() {
        return OracleCloudProvider.INSTANCE;
    }
}
