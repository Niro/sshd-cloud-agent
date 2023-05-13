package com.antonzhdanov.apache.sshd.agent.cloud.oracle;

import com.antonzhdanov.apache.sshd.agent.cloud.signature.BuiltInSignatureAlgorithm;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithm;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithmMapper;
import com.oracle.bmc.keymanagement.model.SignDataDetails;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class OracleSignatureAlgorithmMapper implements SignatureAlgorithmMapper<SignDataDetails.SigningAlgorithm, SignatureAlgorithm> {

    private static final Map<SignatureAlgorithm, SignDataDetails.SigningAlgorithm> SIGN_ALGO_AWS_MAPPING = new HashMap<>() {{
        put(BuiltInSignatureAlgorithm.RSA_PCKS1_V15_SHA256, SignDataDetails.SigningAlgorithm.Sha256RsaPkcs1V15);
        put(BuiltInSignatureAlgorithm.RSA_PCKS1_V15_SHA384, SignDataDetails.SigningAlgorithm.Sha384RsaPkcs1V15);
        put(BuiltInSignatureAlgorithm.RSA_PCKS1_V15_SHA512, SignDataDetails.SigningAlgorithm.Sha512RsaPkcs1V15);
        put(BuiltInSignatureAlgorithm.ECDSA_SHA_256, SignDataDetails.SigningAlgorithm.EcdsaSha256);
        put(BuiltInSignatureAlgorithm.ECDSA_SHA_384, SignDataDetails.SigningAlgorithm.EcdsaSha384);
        put(BuiltInSignatureAlgorithm.ECDSA_SHA_512, SignDataDetails.SigningAlgorithm.EcdsaSha512);
    }};

    @Override
    public Optional<SignDataDetails.SigningAlgorithm> map(SignatureAlgorithm algorithm) {
        return Optional.ofNullable(SIGN_ALGO_AWS_MAPPING.get(algorithm));
    }
}
