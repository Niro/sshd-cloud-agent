package com.antonzhdanov.apache.sshd.agent.cloud.vault.transit;

import com.antonzhdanov.apache.sshd.agent.cloud.AbstractSigner;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithm;
import com.antonzhdanov.apache.sshd.agent.cloud.vault.transit.exception.VaultTransitCloudSshAgentException;
import com.jayway.jsonpath.JsonPath;

import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

public class VaultTransitSigner extends AbstractSigner<VaultTransitCloudKeyInfo> {

    private static final Pattern SIGNATURE_RESPONSE_PATTERN = Pattern.compile("^vault:v\\d+:(?<signature>\\S+)$");
    private static final String VAULT_TRANSIT_SIGN_PATH_TEMPLATE = "/v1/transit/sign/%s/%s";
    private static final String VAULT_TRANSIT_SIGN_BODY_TEMPLATE = "{\"input\": \"%s\", \"signature_algorithm\": \"pkcs1v15\"}";

    private final VaultTransitClient vaultTransitClient;
    private final VaultTransitSignatureAlgorithmMapper vaultTransitSignatureAlgorithmMapper;

    public VaultTransitSigner(VaultTransitClient vaultTransitClient,
                              VaultTransitSignatureAlgorithmMapper vaultTransitSignatureAlgorithmMapper) {
        super(VaultTransitCloudKeyInfo.class);
        this.vaultTransitClient = requireNonNull(vaultTransitClient, "vaultTransitClient");
        this.vaultTransitSignatureAlgorithmMapper = requireNonNull(vaultTransitSignatureAlgorithmMapper, "vaultTransitSignatureAlgorithmMapper");
    }

    @Override
    public byte[] sign(byte[] data, VaultTransitCloudKeyInfo keyInfo, SignatureAlgorithm algorithm) {
        try {
            String vaultKnownAlgo = vaultTransitSignatureAlgorithmMapper.map(algorithm).orElseThrow();

            String response = vaultTransitClient.signData(String.format(VAULT_TRANSIT_SIGN_PATH_TEMPLATE, keyInfo.getKeyId(), vaultKnownAlgo),
                    String.format(VAULT_TRANSIT_SIGN_BODY_TEMPLATE, Base64.getEncoder().encodeToString(data)));

            String signature = JsonPath.read(response, "$.data.signature");

            Matcher signatureMatcher = SIGNATURE_RESPONSE_PATTERN.matcher(signature);

            if (!signatureMatcher.matches()) {
                throw new VaultTransitCloudSshAgentException("Response is not matched against " +
                        SIGNATURE_RESPONSE_PATTERN.pattern() + ", string: [" + signature.substring(0, 20) + "...]");
            }

            return Base64.getDecoder().decode(signatureMatcher.group("signature"));
        } catch (Exception exc) {
            throw new VaultTransitCloudSshAgentException("Signature error", exc);
        }
    }
}
