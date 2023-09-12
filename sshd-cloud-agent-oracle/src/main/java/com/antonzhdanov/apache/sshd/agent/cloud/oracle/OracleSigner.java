package com.antonzhdanov.apache.sshd.agent.cloud.oracle;

import com.antonzhdanov.apache.sshd.agent.cloud.AbstractSigner;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithm;
import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithmMapper;
import com.oracle.bmc.keymanagement.KmsCrypto;
import com.oracle.bmc.keymanagement.model.SignDataDetails;
import com.oracle.bmc.keymanagement.requests.SignRequest;
import com.oracle.bmc.keymanagement.responses.SignResponse;

import java.util.Base64;

public class OracleSigner extends AbstractSigner<OracleCloudKeyInfo> {

    private final KmsCrypto kmsCrypto;
    private final SignatureAlgorithmMapper<SignDataDetails.SigningAlgorithm, SignatureAlgorithm> signatureAlgorithmMapper;

    public OracleSigner(KmsCrypto kmsCrypto, SignatureAlgorithmMapper<SignDataDetails.SigningAlgorithm, SignatureAlgorithm> signatureAlgorithmMapper) {
        super(OracleCloudKeyInfo.class);
        this.kmsCrypto = kmsCrypto;
        this.signatureAlgorithmMapper = signatureAlgorithmMapper;
    }

    @Override
    public byte[] sign(byte[] data, OracleCloudKeyInfo keyInfo, SignatureAlgorithm algorithm) {
        SignDataDetails dataDetails = SignDataDetails.builder()
                .signingAlgorithm(signatureAlgorithmMapper.map(algorithm).orElseThrow())
                .keyId(keyInfo.getKeyId())
                .message(Base64.getEncoder().encodeToString(data))
                .messageType(SignDataDetails.MessageType.Raw)
                .build();

        SignResponse signResponse = kmsCrypto.sign(SignRequest.builder().signDataDetails(dataDetails).build());

        return Base64.getDecoder()
                .decode(signResponse.getSignedData().getSignature());
    }
}
