# SSHD Cloud Agent - AWS Implementation

Used API
* [Get Key](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-key/get-key?tabs=HTTP)
* [Sign](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/sign/sign?tabs=HTTP)

## Example

### Dependencies

```xml
<dependencies>
    <dependency>
        <groupId>com.antonzhdanov</groupId>
        <artifactId>sshd-cloud-agent-azure</artifactId>
        <version>${sshd-cloud-agent.version}</version>
    </dependency>

    <!--  You should provide dependency for AWS Key Vault API Client  -->
    <dependency>
        <groupId>com.azure</groupId>
        <artifactId>azure-security-keyvault-keys</artifactId>
    </dependency>
</dependencies>
```

### Configure SSH Agent Factory

```java
import org.apache.sshd.client.SshClient;
import software.amazon.awssdk.services.kms.KmsClient;

public class SetupExample {
    
    // You should have SshClient and KmsClient
    public void configureSshClient(SshClient sshClient) {
        // Using factory method 'of' to pass instance of AzureCloudSshAgentProvider
        CloudSshAgentFactory<AzureCloudKeyInfo> sshAgentFactory = SingleCloudSshAgentFactory.of(new AzureCloudSshAgentProvider(this::createCryptographyClient));

        // Assign created factory to SshClient
        sshClient.setAgentFactory(sshAgentFactory);
    }

    // Azure Key Vault API Client can be configured only for specific key
    public CryptographyClient createCryptographyClient(AzureCloudKeyInfo keyInfo) {
        return new CryptographyClientBuilder()
                .keyIdentifier(keyInfo.getKeyId())
                .credential(new DefaultAzureCredentialBuilder().build())
                .buildClient();

    }
}
```

### Auth

```java
import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.aws.AwsCloudKeyInfo;

public class AuthExample {
    public void connectAndAuth(CloudSshAgentFactory<AzureCloudKeyInfo> agentFactory,
                               SshClient sshClient, String user, String host, int port) {

        CloudKeyInfo azureManagedKeyInfo = new AzureCloudKeyInfo("KEY-ID");

        // First create session for given user, host and port
        try (ClientSession session = sshClient.connect(user, host, port)
                .verify(Duration.ofSeconds(5)).getSession()) {
            
            // Tell CloudSshAgentFactory that you are going to authorize with azureManagedKeyInfo within session
            // CloudSshAgentFactory#withKeyInfo returns AutoCloseable. Use it to clear useless data after auth
            try (var unused = agentFactory.withKeyInfo(session, awsKmsManagedKeyInfo)) {
                session.auth().verify(Duration.ofSeconds(10));
            }
        }
    }
}
```

See also:
* [AzureIntegrationTest](..%2Fsshd-cloud-agent-test%2Fsrc%2Ftest%2Fjava%2Fcom%2Fantonzhdanov%2Fapache%2Fsshd%2Fagent%2Fcloud%2Fazure%2FAzureIntegrationTest.java)
* [AbstractIntegrationTest](..%2Fsshd-cloud-agent-test%2Fsrc%2Ftest%2Fjava%2Fcom%2Fantonzhdanov%2Fapache%2Fsshd%2Fagent%2Fcloud%2FAbstractIntegrationTest.java)