package com.antonzhdanov.apache.sshd.agent.cloud.signature;

import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.der.DERParser;

import java.io.StreamCorruptedException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;

public class DefaultSignaturePostProcessor implements SignaturePostProcessor {
    @Override
    public byte[] postProcessSignature(byte[] signature, PublicKey publicKey) {
        if (publicKey instanceof ECPublicKey) {
            return postProcessEcSignature(signature);
        }

        return signature;
    }

    /*
        https://www.rfc-editor.org/rfc/rfc6979#section-2.4

        <...> a common way is to use a DER-encoded ASN.1 structure (a SEQUENCE
        of two INTEGERs, for r and s, in that order).
     */
    private byte[] postProcessEcSignature(byte[] sig) {
        try (DERParser parser = new DERParser(sig)) {
            int type = parser.read();
            if (type != 0x30) {
                throw new StreamCorruptedException(
                        "Invalid signature format - not a DER SEQUENCE: 0x" + Integer.toHexString(type));
            }

            // length of remaining encoding of the 2 integers
            int remainLen = parser.readLength();
            /*
             * There are supposed to be 2 INTEGERs, each encoded with:
             *
             * - one byte representing the fact that it is an INTEGER - one byte of the integer encoding length - at
             * least one byte of integer data (zero length is not an option)
             */
            if (remainLen < (2 * 3)) {
                throw new StreamCorruptedException("Invalid signature format - not enough encoded data length: " + remainLen);
            }

            BigInteger r = parser.readBigInteger();
            BigInteger s = parser.readBigInteger();
            // Write the <r,s> to its own types writer.
            Buffer rsBuf = new ByteArrayBuffer();
            rsBuf.putMPInt(r);
            rsBuf.putMPInt(s);

            return rsBuf.getCompactData();
        } catch (Exception exc) {
            throw new RuntimeException(exc);
        }
    }
}
