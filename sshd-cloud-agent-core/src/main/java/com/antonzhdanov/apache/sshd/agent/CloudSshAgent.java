package com.antonzhdanov.apache.sshd.agent;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.PublicKeyLoader;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.Signature;
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
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;

public class CloudSshAgent<K extends CloudKeyInfo> extends AbstractLoggingBean implements SshAgent {

    private final Signer<K> signer;
    private final PublicKeyLoader<K> publicKeyLoader;
    private final List<K> keyInfos;
    private final SignatureAlgorithmMapper<SignatureAlgorithm, String> signatureAlgorithmMapper;

    private final List<PublicKeyWithComment> identities = new CopyOnWriteArrayList<>();
    private final AtomicBoolean initialized = new AtomicBoolean(false);

    public CloudSshAgent(Signer<K> signer,
                         PublicKeyLoader<K> publicKeyLoader,
                         List<K> keyInfos, SignatureAlgorithmMapper<SignatureAlgorithm, String> signatureAlgorithmMapper) {
        this.signer = requireNonNull(signer, "signer");
        this.publicKeyLoader = requireNonNull(publicKeyLoader, "publicKeyProvider");
        this.keyInfos = requireNonNull(keyInfos, "keyInfos");
        this.signatureAlgorithmMapper = requireNonNull(signatureAlgorithmMapper, "signatureAlgorithmMapper");
    }

    @Override
    public Iterable<PublicKeyWithComment> getIdentities() throws IOException {
        try {
            init();
        } catch (Exception exc) {
            throw new SshException("Error collecting public keys from cloud platform", exc);
        }

        return Collections.unmodifiableList(identities);
    }

    @Override
    public SignatureWithAlgorithm sign(SessionContext session, PublicKey key, String algo, byte[] data) throws IOException {
        if (!signer.supports(key)) {
            throw new SshException("Unsupported cloud key");
        }

        try {
            @SuppressWarnings("unchecked")
            CloudPublicKey<K, ? extends PublicKey> cloudPublicKey = (CloudPublicKey<K, ? extends PublicKey>) key;
            Signature signature = signer.sign(data, cloudPublicKey.getCloudKeyInfo(), signatureAlgorithmMapper.map(algo).get());

            return new SignatureWithAlgorithm(signature.getBytes(), signature.getSignatureAlgorithm().toKnownAlgorithm());
        } catch (Exception exc) {
            throw new SshException("Signature error", exc);
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
        if (!initialized.get()) {
            synchronized (this) {
                if (initialized.compareAndSet(false, true)) {
                    try {
                        List<CompletableFuture<CloudPublicKey<K, ? extends PublicKey>>> publicKeyFutures = keyInfos.stream()
                                .map(publicKeyLoader::getPublicKey)
                                .collect(Collectors.toList());

                        List<PublicKeyWithComment> publicKeys = publicKeyFutures.stream()
                                .map(CompletableFuture::join)
                                .map(key -> new PublicKeyWithComment(key, key.getCloudKeyInfo().getComment()))
                                .collect(Collectors.toList());

                        identities.addAll(publicKeys);
                    } catch (Exception exc) {
                        initialized.set(false);
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
