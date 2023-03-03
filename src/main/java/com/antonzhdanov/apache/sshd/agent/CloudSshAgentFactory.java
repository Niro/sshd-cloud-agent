package com.antonzhdanov.apache.sshd.agent;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.implementation.aws.AwsCloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.implementation.aws.AwsPublicKeyLoader;
import com.antonzhdanov.apache.sshd.agent.cloud.implementation.aws.AwsSignatureAlgorithmMapper;
import com.antonzhdanov.apache.sshd.agent.cloud.implementation.aws.AwsSigner;
import com.antonzhdanov.apache.sshd.agent.cloud.implementation.google.GoogleCloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.implementation.google.GooglePublicKeyLoader;
import com.antonzhdanov.apache.sshd.agent.cloud.implementation.google.GoogleSigner;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SshdSignatureAlgorithmMapper;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.agent.SshAgentServer;
import org.apache.sshd.agent.local.ProxyAgentFactory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.channel.ChannelFactory;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import software.amazon.awssdk.services.kms.KmsAsyncClient;

import java.util.List;
import java.util.function.Supplier;

import static java.util.Collections.unmodifiableList;
import static java.util.Objects.requireNonNull;

public class CloudSshAgentFactory<K extends CloudKeyInfo> implements SshAgentFactory {

    private final Supplier<SshAgent> sshAgentSupplier;

    protected CloudSshAgentFactory(Supplier<SshAgent> sshAgentSupplier) {
        this.sshAgentSupplier = requireNonNull(sshAgentSupplier, "sshAgentSupplier");
    }

    @Override
    public List<ChannelFactory> getChannelForwardingFactories(FactoryManager manager) {
        return new ProxyAgentFactory().getChannelForwardingFactories(manager);
    }

    @Override
    public SshAgent createClient(Session session, FactoryManager manager) {
        return sshAgentSupplier.get();
    }

    @Override
    public SshAgentServer createServer(ConnectionService service) {
        throw new UnsupportedOperationException();
    }

    public static SshAgentFactory fowAws(KmsAsyncClient client, List<AwsCloudKeyInfo> keyInfos) {
        return new CloudSshAgentFactory<>(new AwsSshAgentSupplier(client, unmodifiableList(keyInfos)));
    }

    public static SshAgentFactory forGoogle(KeyManagementServiceClient client, List<GoogleCloudKeyInfo> keyInfos) {
        return new CloudSshAgentFactory<>(new GoogleSshAgentSupplier(client, unmodifiableList(keyInfos)));
    }

    private static class AwsSshAgentSupplier implements Supplier<SshAgent> {

        private final KmsAsyncClient kmsAsyncClient;
        private final List<AwsCloudKeyInfo> awsCloudKeyInfos;

        private AwsSshAgentSupplier(KmsAsyncClient kmsAsyncClient, List<AwsCloudKeyInfo> awsCloudKeyInfos) {
            this.kmsAsyncClient = requireNonNull(kmsAsyncClient, "kmsAsyncClient");
            this.awsCloudKeyInfos = requireNonNull(awsCloudKeyInfos, "awsCloudKeyInfos");
        }

        @Override
        public CloudSshAgent<AwsCloudKeyInfo> get() {
            return new CloudSshAgent<>(new AwsSigner(kmsAsyncClient, new AwsSignatureAlgorithmMapper()),
                    new AwsPublicKeyLoader(kmsAsyncClient, new CloudPublicKeyFactory()),
                    awsCloudKeyInfos, new SshdSignatureAlgorithmMapper());
        }
    }

    private static class GoogleSshAgentSupplier implements Supplier<SshAgent> {

        private final KeyManagementServiceClient keyManagementServiceClient;
        private final List<GoogleCloudKeyInfo> googleCloudKeyInfos;

        private GoogleSshAgentSupplier(KeyManagementServiceClient keyManagementServiceClient, List<GoogleCloudKeyInfo> googleCloudKeyInfos) {
            this.keyManagementServiceClient = requireNonNull(keyManagementServiceClient, "keyManagementServiceClient");
            this.googleCloudKeyInfos = requireNonNull(googleCloudKeyInfos, "googleCloudKeyInfos");
        }

        @Override
        public SshAgent get() {
            return new CloudSshAgent<>(new GoogleSigner(keyManagementServiceClient),
                    new GooglePublicKeyLoader(keyManagementServiceClient, new CloudPublicKeyFactory()),
                    googleCloudKeyInfos, new SshdSignatureAlgorithmMapper());
        }
    }
}
