package com.antonzhdanov.apache.sshd.agent.cloud.implementation.google;

import com.antonzhdanov.apache.sshd.agent.cloud.CloudKeyInfo;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithm;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import lombok.Builder;
import lombok.Data;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

@Builder
@Data
public class GoogleCloudKeyInfo implements CloudKeyInfo {

    private static final Pattern RESOURCE_NAME_PATTERN = Pattern.compile("^projects/(?<project>\\S+)" +
            "/locations/(?<location>\\S+)" +
            "/keyRings/(?<keyRing>\\S+)" +
            "/cryptoKeys/(?<cryptoKey>\\S+)" +
            "/cryptoKeyVersions/(?<cryptoVersion>\\S+)$");
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
            throw new RuntimeException("Invalid resource name " + resourceName);
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

    public CryptoKeyVersionName toCryptoKeyVersionName() {
        return CryptoKeyVersionName.of(getProject(), getLocation(), getKeyRing(), getCryptoKey(), getCryptoKeyVersion());
    }
}
