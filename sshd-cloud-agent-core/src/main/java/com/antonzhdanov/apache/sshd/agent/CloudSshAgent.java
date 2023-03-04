package com.antonzhdanov.apache.sshd.agent;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.PublicKeyLoader;
import com.antonzhdanov.apache.sshd.agent.cloud.exception.CloudSshAgentException;
import com.antonzhdanov.apache.sshd.agent.cloud.Signer;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithm;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithmMapper;
import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentKeyConstraint;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.AbstractMap;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.util.Objects.requireNonNull;

public class CloudSshAgent<K extends CloudKeyInfo> extends AbstractLoggingBean implements SshAgent {

    private final Signer<K> signer;
    private final PublicKeyLoader<K> publicKeyLoader;
    private final K keyInfo;
    private final SignatureAlgorithmMapper<SignatureAlgorithm, String> signatureAlgorithmMapper;

    private final AtomicBoolean publicKeyLoaded = new AtomicBoolean(false);
    private CloudPublicKey<K, ? extends PublicKey> cloudPublicKey;

    public CloudSshAgent(Signer<K> signer,
                         PublicKeyLoader<K> publicKeyLoader,
                         K keyInfo,
                         SignatureAlgorithmMapper<SignatureAlgorithm, String> signatureAlgorithmMapper) {
        this.signer = requireNonNull(signer, "signer");
        this.publicKeyLoader = requireNonNull(publicKeyLoader, "publicKeyLoader");
        this.keyInfo = requireNonNull(keyInfo, "keyInfo");
        this.signatureAlgorithmMapper = requireNonNull(signatureAlgorithmMapper, "signatureAlgorithmMapper");
    }

    @Override
    public Iterable<PublicKeyWithComment> getIdentities() throws IOException {
        try {
            init();
        } catch (Exception exc) {
            throw new SshException("Error collecting public keys from cloud platform", exc);
        }

        requireNonNull(cloudPublicKey, "Public key is not loaded");

        return Collections.singleton(new PublicKeyWithComment(cloudPublicKey, cloudPublicKey.getCloudKeyInfo().getComment()));
    }

    @Override
    public SignatureWithAlgorithm sign(SessionContext session, PublicKey key, String algo, byte[] data) throws IOException {
        if (!signer.supports(key)) {
            throw new CloudSshAgentException("Unsupported cloud key");
        }

        try {
            @SuppressWarnings("unchecked")
            CloudPublicKey<K, ? extends PublicKey> cloudPublicKey = (CloudPublicKey<K, ? extends PublicKey>) key;
            SignatureAlgorithm signatureAlgorithm = signatureAlgorithmMapper.map(algo)
                    .orElseThrow(() -> new UnsupportedOperationException("Unknown signature algorithm " + algo));

            byte[] signature = signer.sign(data, cloudPublicKey.getCloudKeyInfo(), signatureAlgorithm);

            return new SignatureWithAlgorithm(signature, algo);
        } catch (Exception exc) {
            throw new CloudSshAgentException("Signature error", exc);
        }
    }

    @Override
    public void addIdentity(KeyPair key, String comment, SshAgentKeyConstraint... constraints) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void removeIdentity(PublicKey key) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void removeAllIdentities() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isOpen() {
        return true;
    }

    @Override
    public void close() {

    }

    private void init() {
        if (!publicKeyLoaded.get()) {
            synchronized (this) {
                if (publicKeyLoaded.compareAndSet(false, true)) {
                    try {
                        cloudPublicKey = publicKeyLoader.getPublicKey(keyInfo);
                    } catch (Exception exc) {
                        publicKeyLoaded.set(false);
                    }
                }
            }
        }
    }

    private static class PublicKeyWithComment extends AbstractMap.SimpleImmutableEntry<PublicKey, String> {
        private PublicKeyWithComment(PublicKey publicKey, String comment) {
            super(requireNonNull(publicKey, "publicKey"), requireNonNull(comment, "comment"));
        }
    }

    private static class SignatureWithAlgorithm extends AbstractMap.SimpleImmutableEntry<String, byte[]> {
        private SignatureWithAlgorithm(byte[] signature, String algorithm) {
            super(requireNonNull(algorithm, "algorithm"), requireNonNull(signature, "signature"));
        }
    }
}
