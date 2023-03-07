package com.antonzhdanov.apache.sshd.agent.cloud.azure.signature;

import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignaturePostProcessor;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

public class JsonWebSignaturePostProcessor implements SignaturePostProcessor {
    @Override
    public byte[] postProcessSignature(byte[] signature, PublicKey publicKey) {
        if (publicKey instanceof ECPublicKey) {
            return postProcessEcSignature(signature);
        }

        return signature;
    }

    /*
        https://www.rfc-editor.org/rfc/rfc7518#page-9
     */
    private byte[] postProcessEcSignature(byte[] signature) {
        int length = signature.length;
        if (length != 64 && length != 96 && length != 132) {
            throw new RuntimeException("Invalid signature");
        }

        BigInteger r = new BigInteger(Arrays.copyOfRange(signature, 0, length / 2));
        BigInteger s = new BigInteger(Arrays.copyOfRange(signature, length / 2, length));

        ByteArrayBuffer byteArrayBuffer = new ByteArrayBuffer();
        byteArrayBuffer.putMPInt(r);
        byteArrayBuffer.putMPInt(s);

        return byteArrayBuffer.getCompactData();
    }
}
