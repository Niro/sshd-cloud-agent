package com.antonzhdanov.apache.sshd.agent.cloud.signature;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.mockito.Mockito.mock;

@Test
public class DefaultSignaturePostProcessorTest {

    private static final String BASE64_EC_DEFAULT_SIGNATURE = "MGUCMQDRV2mbmuF/CdDfnzxCogyVtT0QfH6Wnot6Ql0GdYm+8Iu44cXDILXhvzBUhDV1aJECMHYIk1eEeo/r7V9g8JW+RQcIZrMdyjJgN6Tq8FhsDziRFK7Tav64aEUGRRE4xy+CHw==";
    private static final String BASE64_EC_VALID_SIGNATURE = "AAAAMQDRV2mbmuF/CdDfnzxCogyVtT0QfH6Wnot6Ql0GdYm+8Iu44cXDILXhvzBUhDV1aJEAAAAwdgiTV4R6j+vtX2Dwlb5FBwhmsx3KMmA3pOrwWGwPOJEUrtNq/rhoRQZFETjHL4If";

    public void testRsaSignatureIsNotProcessed() {
        // GIVEN
        byte[] signature = new byte[0];
        RSAPublicKey publicKey = mock(RSAPublicKey.class);

        DefaultSignaturePostProcessor signaturePostProcessor = new DefaultSignaturePostProcessor();

        // WHEN
        byte[] postProcessedSignature = signaturePostProcessor.postProcessSignature(signature, publicKey);

        // THEN
        Assert.assertEquals(postProcessedSignature, signature);
    }

    public void testEcSignatureIsProcessed() {
        // GIVEN
        byte[] signature = Base64.getDecoder().decode(BASE64_EC_DEFAULT_SIGNATURE);
        ECPublicKey publicKey = mock(ECPublicKey.class);

        DefaultSignaturePostProcessor signaturePostProcessor = new DefaultSignaturePostProcessor();

        // WHEN
        byte[] postProcessedSignature = signaturePostProcessor.postProcessSignature(signature, publicKey);

        // THEN
        Assert.assertEquals(postProcessedSignature, Base64.getDecoder().decode(BASE64_EC_VALID_SIGNATURE));
    }
}