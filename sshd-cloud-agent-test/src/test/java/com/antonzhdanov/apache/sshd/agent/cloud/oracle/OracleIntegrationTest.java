package com.antonzhdanov.apache.sshd.agent.cloud.oracle;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgentFactory;
import com.antonzhdanov.apache.sshd.agent.SingleCloudSshAgentFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.AbstractIntegrationTest;
import com.oracle.bmc.Region;
import com.oracle.bmc.auth.SimpleAuthenticationDetailsProvider;
import com.oracle.bmc.keymanagement.KmsCrypto;
import com.oracle.bmc.keymanagement.KmsCryptoClient;
import com.oracle.bmc.keymanagement.KmsManagement;
import com.oracle.bmc.keymanagement.KmsManagementClient;
import org.testng.annotations.DataProvider;

import java.io.ByteArrayInputStream;

import static com.antonzhdanov.apache.sshd.agent.cloud.TestUtils.readEnv;

public class OracleIntegrationTest extends AbstractIntegrationTest<OracleCloudKeyInfo> {

    private static final String TENANT_ID = "ORACLE_TENANT_ID";
    private static final String USER_ID = "ORACLE_USER_ID";
    private static final String FINGERPRINT = "ORACLE_FINGERPRINT";
    private static final String REGION = "ORACLE_REGION";
    private static final String PRIVATE_KEY = "ORACLE_PRIVATE_KEY";
    private static final String MANAGEMENT_ENDPOINT = "ORACLE_MANAGEMENT_ENDPOINT";
    private static final String CRYPTO_ENDPOINT = "ORACLE_CRYPTO_ENDPOINT";

    private final SimpleAuthenticationDetailsProvider detailsProvider = SimpleAuthenticationDetailsProvider.builder()
            .tenantId(readEnv(TENANT_ID))
            .userId(readEnv(USER_ID))
            .fingerprint(readEnv(FINGERPRINT))
            .region(Region.fromRegionId(readEnv(REGION)))
            .privateKeySupplier(() -> new ByteArrayInputStream(readEnv(PRIVATE_KEY).getBytes())).build();

    @Override
    @DataProvider
    protected Object[][] testData() {
        return new Object[][] {
                {"oracle/ECDSA-256.pub", new OracleCloudKeyInfo("ocid1.key.oc1.eu-frankfurt-1.dzsfuxzjaaesw.abtheljrlz2f36gfftc676qsz2c6jjayiqjsbzcmlm6snedynts3tfbkmfzq",
                        "ocid1.keyversion.oc1.eu-frankfurt-1.dzsfuxzjaaesw.beeumrplmryaa.abtheljr7vtnrytudevrvaahb23rmmnyfgsshlrhwir4p2lq2vmt2zr7auma")},
                {"oracle/ECDSA-384.pub", new OracleCloudKeyInfo("ocid1.key.oc1.eu-frankfurt-1.dzsfuxzjaaesw.abtheljs4vkyvbhd6fn7xx5zd2lagvulemsyzkn2bxpu6ww474pk3h5n2qsa",
                        "ocid1.keyversion.oc1.eu-frankfurt-1.dzsfuxzjaaesw.beurmrpvcfyaa.abtheljscs6lyxo2jmejuupyjhwsojpmrcek7jxo7y5o5khqt4yqgib2ppkq")},
                {"oracle/ECDSA-521.pub", new OracleCloudKeyInfo("ocid1.key.oc1.eu-frankfurt-1.dzsfuxzjaaesw.abtheljs3qheqymntkogmhehidprrgooq4os6uppfwex2loi7wwe3ctq4weq",
                        "ocid1.keyversion.oc1.eu-frankfurt-1.dzsfuxzjaaesw.bfarmrpvckaaa.abtheljsir4eykwkqskhxm63coggdbtysrk5vc5g3jpjlsqz65nuul2dc2ya")},
        };
    }

    @Override
    protected CloudSshAgentFactory<OracleCloudKeyInfo> createCloudFactory() throws Exception {
        return SingleCloudSshAgentFactory.of(new OracleCloudSshAgentProvider(createKmsManagement(), createKmsCrypto()));
    }

    private KmsManagement createKmsManagement() {
        return KmsManagementClient.builder()
                .endpoint(readEnv(MANAGEMENT_ENDPOINT))
                .build(detailsProvider);
    }

    private KmsCrypto createKmsCrypto() {
        return KmsCryptoClient.builder()
                .endpoint(readEnv(CRYPTO_ENDPOINT))
                .build(detailsProvider);
    }
}
