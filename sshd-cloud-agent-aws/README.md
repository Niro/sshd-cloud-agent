# SSHD Cloud Agent - AWS Implementation

Used API
* [GetPublicKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GetPublicKey.html)
* [Sign](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html)

## Example

### Dependencies

```xml
<dependencies>
    <dependency>
        <groupId>com.antonzhdanov</groupId>
        <artifactId>sshd-cloud-agent-aws</artifactId>
        <version>${sshd-cloud-agent.version}</version>
    </dependency>

    <!--  You should provide dependency for AWS Key Management Service (KMS) API Client  -->
    <dependency>
        <groupId>software.amazon.awssdk</groupId>
        <artifactId>kms</artifactId>
    </dependency>
</dependencies>
```

### Configure SSH Agent Factory

```java
import org.apache.sshd.client.SshClient;
import software.amazon.awssdk.services.kms.KmsClient;

public class SetupExample {
    
    // You should have SshClient and KmsClient
    public void configureSshClient(SshClient sshClient, KmsClient kmsClient) {
        // Using factory method 'of' to pass instance of AwsCloudSshAgentProvider
        CloudSshAgentFactory<AwsCloudKeyInfo> sshAgentFactory = SingleCloudSshAgentFactory.of(new AwsCloudSshAgentProvider(kmsClient));

        // Assign created factory to SshClient
        sshClient.setAgentFactory(sshAgentFactory);
    }
}
```

### Auth

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
* [AwsIntegrationTest](..%2Fsshd-cloud-agent-test%2Fsrc%2Ftest%2Fjava%2Fcom%2Fantonzhdanov%2Fapache%2Fsshd%2Fagent%2Fcloud%2Faws%2FAwsIntegrationTest.java)
* [AbstractIntegrationTest](..%2Fsshd-cloud-agent-test%2Fsrc%2Ftest%2Fjava%2Fcom%2Fantonzhdanov%2Fapache%2Fsshd%2Fagent%2Fcloud%2FAbstractIntegrationTest.java)