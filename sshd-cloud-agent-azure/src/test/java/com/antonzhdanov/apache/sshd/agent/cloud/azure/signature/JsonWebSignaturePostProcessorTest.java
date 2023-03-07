package com.antonzhdanov.apache.sshd.agent.cloud.azure.signature;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.mockito.Mockito.mock;
import static org.testng.Assert.assertEquals;

@Test
public class JsonWebSignaturePostProcessorTest {

    private static final String LENGTH64_SIG = "eTsGRyjzW+3jM1l6+6K4JQ8Y3xd26FgH+yFNTKyLTS4ZN2b8LGD0ssXcogI3lDMIMz0SoFl32Lol0XrI4rBjuQ==";
    private static final String LENGTH96_SIG = "8D7Ze/usy5+fBzJZmGEFFTJkIx1q2G8r9Ka9S7UvtBKqW5y8WX7wH7akONMylshuKUTfs5M1bzcD/VY5jdTrxJkNTB6lrDbU7My/ZzN2vC309SC79qJpNTPG+hosXB5x";
    private static final String LENGTH132_SIG = "AV1zKVGWSRqjnI9otjRbFiOiY7Ff5tXFMj9dxnPzlRwkxa6P+CR1bu/DthZbFOis4p+ObaALKKnH6K5cDKKWZNomAEdZyYu9tJIxd3R60HNUcunecsL3LKqAvCcgQo3aQ5FHdL91am5DdH8lWTkA4Ff6e6EDZnJSfL9VoKHZfVlPR2Lc";

    private static final String LENGTH64_VALID_SIG = "AAAAIHk7Bkco81vt4zNZevuiuCUPGN8XduhYB/shTUysi00uAAAAIBk3ZvwsYPSyxdyiAjeUMwgzPRKgWXfYuiXResjisGO5";
    private static final String LENGTH96_VALID_SIG = "AAAAMQDwPtl7+6zLn58HMlmYYQUVMmQjHWrYbyv0pr1LtS+0EqpbnLxZfvAftqQ40zKWyG4AAAAwKUTfs5M1bzcD/VY5jdTrxJkNTB6lrDbU7My/ZzN2vC309SC79qJpNTPG+hosXB5x";
    private static final String LENGTH132_VALID_SIG = "AAAAQgFdcylRlkkao5yPaLY0WxYjomOxX+bVxTI/XcZz85UcJMWuj/gkdW7vw7YWWxTorOKfjm2gCyipx+iuXAyilmTaJgAAAEFHWcmLvbSSMXd0etBzVHLp3nLC9yyqgLwnIEKN2kORR3S/dWpuQ3R/JVk5AOBX+nuhA2ZyUny/VaCh2X1ZT0di3A==";

    @DataProvider
    public Object[][] signatureDataProvider() {
        return new Object[][] {
                {Base64.getDecoder().decode(LENGTH64_SIG), Base64.getDecoder().decode(LENGTH64_VALID_SIG)},
                {Base64.getDecoder().decode(LENGTH96_SIG), Base64.getDecoder().decode(LENGTH96_VALID_SIG)},
                {Base64.getDecoder().decode(LENGTH132_SIG), Base64.getDecoder().decode(LENGTH132_VALID_SIG)}
        };
    }

    public void testRsaSignatureIsNotProcessed() {
        // GIVEN
        byte[] signature = new byte[0];
        RSAPublicKey publicKey = mock(RSAPublicKey.class);

        JsonWebSignaturePostProcessor signaturePostProcessor = new JsonWebSignaturePostProcessor();

        // WHEN
        byte[] postProcessedSignature = signaturePostProcessor.postProcessSignature(signature, publicKey);

        // THEN
        assertEquals(postProcessedSignature, signature);
    }

    @Test(dataProvider = "signatureDataProvider")
    public void testEcJwaSignatureProcessed(byte[] jwaSignature, byte[] expected) {
        // GIVEN
        JsonWebSignaturePostProcessor signaturePostProcessor = new JsonWebSignaturePostProcessor();
        ECPublicKey publicKey = mock(ECPublicKey.class);

        // WHEN
        byte[] postProcessedSignature = signaturePostProcessor.postProcessSignature(jwaSignature, publicKey);

        // THEN
        assertEquals(postProcessedSignature, expected);
    }
}