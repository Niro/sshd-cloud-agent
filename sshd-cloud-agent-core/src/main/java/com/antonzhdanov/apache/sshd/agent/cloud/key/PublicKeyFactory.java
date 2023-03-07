package com.antonzhdanov.apache.sshd.agent.cloud.key;

import org.apache.sshd.common.cipher.ECCurves;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

public interface PublicKeyFactory {
    PublicKey create(String pem);

    PublicKey create(byte[] encoded);

    RSAPublicKey create(BigInteger modulus, BigInteger publicExponent);

    ECPublicKey create(BigInteger x, BigInteger y, ECCurves ecCurve);
}
