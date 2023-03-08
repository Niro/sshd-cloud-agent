# Apache SSHD Cloud Agent
![latest version](https://img.shields.io/maven-central/v/com.antonzhdanov/sshd-cloud-agent)

SSHD extension for client auth using SSH Key from cloud

## Supported Cloud Providers

- [x] Amazon
- [x] Google
- [x] Azure
- [ ] Yandex - no API for asymmetric sign?
- [ ] Alibaba
- [ ] Tencent Cloud

## Single Cloud Provider
### AWS
Refer to [sshd-cloud-agent-aws/README.md](sshd-cloud-agent-aws%2FREADME.md)

### Azure
Refer to [sshd-cloud-agent-azure/README.md](sshd-cloud-agent-azure%2FREADME.md)

### Google
Refer to [sshd-cloud-agent-google/README.md](sshd-cloud-agent-google%2FREADME.md)

## Multiple Cloud Providers

Examples above shows how to use only one cloud provider for SshClient. But it is also possible to configure SshClient to support multiple cloud providers

### Dependencies

Add dependencies for each needed cloud implementation using instructions above

### Configure SSH Agent Factory

```java
import org.apache.sshd.client.SshClient;
import software.amazon.awssdk.services.kms.KmsClient;

public class SetupExample {

    // You should have SshClient and all API Clients you want to use
    public void configureSshClient(SshClient sshClient,
                                   KeyManagementServiceClient googleClient,
                                   KmsClient awsClient,
                                   CryptographyClientProvider azureClientProvider) {
        // Using factory method 'of' pass a list of CloudSshAgentProvider instances
        CloudSshAgentFactory<AwsCloudKeyInfo> sshAgentFactory = MultiCloudSshAgentFactory.of(
                Arrays.asList(
                        new AzureCloudSshAgentProvider(azureClientProvider),
                        new AwsCloudSshAgentProvider(awsClient),
                        new GoogleCloudSshAgentProvider(googleClient)
                )
        );

        // Assign created factory to SshClient
        sshClient.setAgentFactory(sshAgentFactory);
    }
}
```

### Auth

The process is the same as for [SingleCloudSshAgentFactory](sshd-cloud-agent-core%2Fsrc%2Fmain%2Fjava%2Fcom%2Fantonzhdanov%2Fapache%2Fsshd%2Fagent%2FSingleCloudSshAgentFactory.java). You should provide CloudSshAgentFactory with CloudKeyInfo you are going to use withing the opened session

```java
import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.aws.AwsCloudKeyInfo;

public class AuthExample {
    public void connectAndAuth(CloudSshAgentFactory<AwsCloudKeyInfo> agentFactory,
                               SshClient sshClient, String user, String host, int port) {

        CloudKeyInfo awsKmsManagedKeyInfo = new AwsCloudKeyInfo("KEY-ID");

        // First create session for given user, host and port
        try (ClientSession session = sshClient.connect(user, host, port)
                .verify(Duration.ofSeconds(5)).getSession()) {
            
            // Tell CloudSshAgentFactory that you are going to authorize with awsKmsManagedKeyInfo within session
            // CloudSshAgentFactory#withKeyInfo returns AutoCloseable. Use it to clear useless data after auth
            try (var unused = agentFactory.withKeyInfo(session, awsKmsManagedKeyInfo)) {
                session.auth().verify(Duration.ofSeconds(10));
            }
        }
    }
}
```

See also:
* [MultiCloudIntegrationTest](sshd-cloud-agent-test%2Fsrc%2Ftest%2Fjava%2Fcom%2Fantonzhdanov%2Fapache%2Fsshd%2Fagent%2Fcloud%2FMultiCloudIntegrationTest.java)
* [AbstractIntegrationTest](..%2Fsshd-cloud-agent-test%2Fsrc%2Ftest%2Fjava%2Fcom%2Fantonzhdanov%2Fapache%2Fsshd%2Fagent%2Fcloud%2FAbstractIntegrationTest.java)
