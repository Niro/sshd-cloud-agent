package com.antonzhdanov.apache.sshd.agent.cloud.google;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.CloudProvider;
import com.antonzhdanov.apache.sshd.agent.cloud.exception.CloudSshAgentException;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithm;
import com.google.cloud.kms.v1.CryptoKeyVersionName;

import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

public class GoogleCloudKeyInfo implements CloudKeyInfo {

    private static final Pattern RESOURCE_NAME_PATTERN = Pattern.compile("^projects/(?<project>\\S+)" +
            "/locations/(?<location>\\S+)" +
            "/keyRings/(?<keyRing>\\S+)" +
            "/cryptoKeys/(?<cryptoKey>\\S+)" +
            "/cryptoKeyVersions/(?<cryptoKeyVersion>\\S+)$");
    private static final String KEY_COMMENT_FORMAT = "Google projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s";

    private final String project;
    private final String location;
    private final String keyRing;
    private final String cryptoKey;
    private final String cryptoKeyVersion;
    private final SignatureAlgorithm signatureAlgorithm;

    public GoogleCloudKeyInfo(String project, String location, String keyRing, String cryptoKey, String cryptoKeyVersion, SignatureAlgorithm signatureAlgorithm) {
        this.project = requireNonNull(project, "project");
        this.location = requireNonNull(location, "location");
        this.keyRing = requireNonNull(keyRing, "keyRing");
        this.cryptoKey = requireNonNull(cryptoKey, "cryptoKey");
        this.cryptoKeyVersion = requireNonNull(cryptoKeyVersion, "cryptoKeyVersion");
        this.signatureAlgorithm = requireNonNull(signatureAlgorithm, "signatureAlgorithm");
    }

    public static GoogleCloudKeyInfo fromResourceName(String resourceName, SignatureAlgorithm signatureAlgorithm) {
        Matcher matcher = RESOURCE_NAME_PATTERN.matcher(resourceName);

        if (!matcher.matches()) {
            throw new CloudSshAgentException("Invalid resource name " + resourceName);
        }

        return GoogleCloudKeyInfo.builder()
                .project(matcher.group("project"))
                .location(matcher.group("location"))
                .keyRing(matcher.group("keyRing"))
                .cryptoKey(matcher.group("cryptoKey"))
                .cryptoKeyVersion(matcher.group("cryptoKeyVersion"))
                .signatureAlgorithm(signatureAlgorithm)
                .build();
    }

    @Override
    public String getComment() {
        return String.format(KEY_COMMENT_FORMAT, project, location, keyRing, cryptoKey, cryptoKeyVersion);
    }

    public String getProject() {
        return project;
    }

    public String getLocation() {
        return location;
    }

    public String getKeyRing() {
        return keyRing;
    }

    public String getCryptoKey() {
        return cryptoKey;
    }

    public String getCryptoKeyVersion() {
        return cryptoKeyVersion;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    @Override
    public CloudProvider getCloudProvider() {
        return GoogleCloudProvider.INSTANCE;
    }

    public CryptoKeyVersionName toCryptoKeyVersionName() {
        return CryptoKeyVersionName.of(getProject(), getLocation(), getKeyRing(), getCryptoKey(), getCryptoKeyVersion());
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }

        GoogleCloudKeyInfo that = (GoogleCloudKeyInfo) obj;
        return project.equals(that.project) &&
                location.equals(that.location) &&
                keyRing.equals(that.keyRing) &&
                cryptoKey.equals(that.cryptoKey) &&
                cryptoKeyVersion.equals(that.cryptoKeyVersion) &&
                signatureAlgorithm.equals(that.signatureAlgorithm);
    }

    @Override
    public int hashCode() {
        return Objects.hash(project, location, keyRing, cryptoKey, cryptoKeyVersion, signatureAlgorithm);
    }

    @Override
    public String toString() {
        return getComment();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String project;
        private String location;
        private String keyRing;
        private String cryptoKey;
        private String cryptoKeyVersion;
        private SignatureAlgorithm signatureAlgorithm;

        public Builder project(String value) {
            this.project = value;
            return this;
        }

        public Builder location(String value) {
            this.location = value;
            return this;
        }

        public Builder keyRing(String value) {
            this.keyRing = value;
            return this;
        }

        public Builder cryptoKey(String value) {
            this.cryptoKey = value;
            return this;
        }

        public Builder cryptoKeyVersion(String value) {
            this.cryptoKeyVersion = value;
            return this;
        }

        public Builder signatureAlgorithm(SignatureAlgorithm value) {
            this.signatureAlgorithm = value;
            return this;
        }

        public GoogleCloudKeyInfo build() {
            return new GoogleCloudKeyInfo(
                    requireNonNull(project, "project"),
                    requireNonNull(location, "location"),
                    requireNonNull(keyRing, "keyRing"),
                    requireNonNull(cryptoKey, "cryptoKey"),
                    requireNonNull(cryptoKeyVersion, "cryptoKeyVersion"),
                    requireNonNull(signatureAlgorithm, "signatureAlgorithm")
            );
        }
    }
}
