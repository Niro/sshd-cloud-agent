package com.antonzhdanov.apache.sshd.agent.cloud;

import com.antonzhdanov.apache.sshd.agent.CloudSshAgentFactory;
import com.antonzhdanov.apache.sshd.agent.MultiCloudSshAgentFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.aws.AwsCloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.aws.AwsCloudSshAgentProvider;
import com.antonzhdanov.apache.sshd.agent.cloud.aws.AwsIntegrationTest;
import com.antonzhdanov.apache.sshd.agent.cloud.azure.AzureCloudSshAgentProvider;
import com.antonzhdanov.apache.sshd.agent.cloud.azure.AzureIntegrationTest;
import com.antonzhdanov.apache.sshd.agent.cloud.google.GoogleCloudSshAgentProvider;
import com.antonzhdanov.apache.sshd.agent.cloud.google.GoogleIntegrationTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;

import java.util.Arrays;

import static com.antonzhdanov.apache.sshd.agent.cloud.google.GoogleIntegrationTest.createKeyInfo;
import static com.antonzhdanov.apache.sshd.agent.cloud.signature.BuiltInSignatureAlgorithm.ECDSA_SHA_256;
import static com.antonzhdanov.apache.sshd.agent.cloud.signature.BuiltInSignatureAlgorithm.ECDSA_SHA_384;
import static com.antonzhdanov.apache.sshd.agent.cloud.signature.BuiltInSignatureAlgorithm.RSA_PCKS1_V15_SHA256;
import static com.antonzhdanov.apache.sshd.agent.cloud.signature.BuiltInSignatureAlgorithm.RSA_PCKS1_V15_SHA512;

public class MultiCloudIntegrationTest extends AbstractIntegrationTest<CloudKeyInfo> {

    @BeforeClass
    @Override
    public void init() throws Exception {
        super.init();
    }

    @Override
    @DataProvider(parallel = true)
    protected Object[][] testData() {
        return new Object[][] {
                {"aws/RSA-2048.pub", new AwsCloudKeyInfo("ecde8af1-4f4b-4ccd-be36-7a8b4409b23f")},
                {"aws/ECC_NIST_P256.pub", new AwsCloudKeyInfo("f827f37f-79ff-44ca-aa0c-843722df8d46")},
//                {"azure/RSA-2048.pub", new AzureCloudKeyInfo("https://sshd-cloud-agent-test.vault.azure.net/keys/RSA-2048/00326446c4ac4276be224f0a40665295")},
//                {"azure/RSA-3072.pub", new AzureCloudKeyInfo("https://sshd-cloud-agent-test.vault.azure.net/keys/RSA-3072/01a660ce5b9c4fb59d1edbfba78d527e")},
//                {"azure/RSA-4096.pub", new AzureCloudKeyInfo("https://sshd-cloud-agent-test.vault.azure.net/keys/RSA-4096/11646053271144719cdf1eea500335a8")},
//                {"azure/EC-P256.pub", new AzureCloudKeyInfo("https://sshd-cloud-agent-test.vault.azure.net/keys/EC-P256/504c3c73266f43c492bc787f7b3762ff")},
//                {"azure/EC-P384.pub", new AzureCloudKeyInfo("https://sshd-cloud-agent-test.vault.azure.net/keys/EC-P384/331ff303c2c043569e198b116e00788f")},
//                {"azure/EC-P521.pub", new AzureCloudKeyInfo("https://sshd-cloud-agent-test.vault.azure.net/keys/EC-P521/1f88fc6e10b04e9c9b3f98fc619742da")},
                {"google/RSA-2048-SHA256.pub", createKeyInfo("RSA-2048-SHA256", RSA_PCKS1_V15_SHA256)},
                {"google/RSA-3072-SHA256.pub", createKeyInfo("RSA-3072-SHA256-1", RSA_PCKS1_V15_SHA256)},
                {"google/RSA-4096-SHA256.pub", createKeyInfo("RSA-4096-SHA256", RSA_PCKS1_V15_SHA256)},
                {"google/RSA-4096-SHA512.pub", createKeyInfo("RSA-4096-SHA512", RSA_PCKS1_V15_SHA512)},
                {"google/ECDSA-256.pub", createKeyInfo("ECDSA-256", ECDSA_SHA_256)},
                {"google/ECDSA-384.pub", createKeyInfo("ECDSA-384", ECDSA_SHA_384)}
        };
    }

    @Override
    protected CloudSshAgentFactory<CloudKeyInfo> createCloudFactory() throws Exception {
        return MultiCloudSshAgentFactory.of(
                Arrays.asList(
                        new AzureCloudSshAgentProvider(AzureIntegrationTest::createCryptographyClient),
                        new AwsCloudSshAgentProvider(AwsIntegrationTest.createKmsClient()),
                        new GoogleCloudSshAgentProvider(GoogleIntegrationTest.createClient())
                )
        );
    }
}
