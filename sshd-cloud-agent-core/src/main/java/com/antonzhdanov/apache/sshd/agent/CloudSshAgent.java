package com.antonzhdanov.apache.sshd.agent;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.PublicKeyLoader;
import com.antonzhdanov.apache.sshd.agent.cloud.Signer;
import com.antonzhdanov.apache.sshd.agent.cloud.exception.CloudSshAgentException;
import com.antonzhdanov.apache.sshd.agent.cloud.key.CloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithm;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithmMapper;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignaturePostProcessor;
import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentKeyConstraint;
import org.apache.sshd.common.session.SessionContext;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.AbstractMap;
import java.util.Collections;

import static java.util.Objects.requireNonNull;

public class CloudSshAgent<K extends CloudKeyInfo> implements SshAgent {

    private final Signer<K> signer;
    private final PublicKeyLoader<K> publicKeyLoader;
    private final SignaturePostProcessor signaturePostProcessor;
    private final K keyInfo;
    private final SignatureAlgorithmMapper<SignatureAlgorithm, String> signatureAlgorithmMapper;

    public CloudSshAgent(Signer<K> signer,
                         PublicKeyLoader<K> publicKeyLoader,
                         SignaturePostProcessor signaturePostProcessor,
                         K keyInfo,
                         SignatureAlgorithmMapper<SignatureAlgorithm, String> signatureAlgorithmMapper) {
        this.signer = requireNonNull(signer, "signer");
        this.publicKeyLoader = requireNonNull(publicKeyLoader, "publicKeyLoader");
        this.signaturePostProcessor = requireNonNull(signaturePostProcessor, "signaturePostProcessor");
        this.keyInfo = requireNonNull(keyInfo, "keyInfo");
        this.signatureAlgorithmMapper = requireNonNull(signatureAlgorithmMapper, "signatureAlgorithmMapper");
    }

    @Override
    public Iterable<PublicKeyWithComment> getIdentities() {
        try {
            CloudPublicKey<K, PublicKey> cloudPublicKey = publicKeyLoader.loadPublicKey(keyInfo);

            return Collections.singleton(new PublicKeyWithComment(cloudPublicKey, cloudPublicKey.getCloudKeyInfo().getComment()));
        } catch (Exception exc) {
            throw new CloudSshAgentException("Unable to load public key with " + publicKeyLoader.getClass().getName(), exc);
        }
    }

    @Override
    public SignatureWithAlgorithm sign(SessionContext session, PublicKey key, String algo, byte[] data) {
        if (!(key instanceof CloudPublicKey)) {
            throw new CloudSshAgentException("This agent supports only cloud key, given key is " +
                    key.getClass().getName());
        }

        if (!signer.supports(key)) {
            throw new CloudSshAgentException("Current signer " +
                    signer.getClass().getName() +
                    " is not supports given key " +
                    key.getClass().getName());
        }

        try {
            @SuppressWarnings("unchecked")
            CloudPublicKey<K, PublicKey> cloudPublicKey = (CloudPublicKey<K, PublicKey>) key;
            SignatureAlgorithm signatureAlgorithm = signatureAlgorithmMapper.map(algo)
                    .orElseThrow(() -> new CloudSshAgentException("Unknown signature algorithm " + algo));

            byte[] signature = signer.sign(data, cloudPublicKey.getCloudKeyInfo(), signatureAlgorithm);

            byte[] processedSignature = signaturePostProcessor.postProcessSignature(signature, cloudPublicKey);

            return new SignatureWithAlgorithm(processedSignature, algo);
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
