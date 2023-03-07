package com.antonzhdanov.apache.sshd.agent.cloud.google;

import com.antonzhdanov.apache.sshd.agent.cloud.signature.SignatureAlgorithm;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

@Test
public class GoogleCloudKeyInfoTest {

    private static final String PROJECT = "PROJECT";
    private static final String LOCATION = "LOCATION";
    private static final String KEY_RING = "KEY_RING";
    private static final String CRYPTO_KEY = "CRYPTO_KEY";
    private static final String VERSION = "VERSION";

    public void testFromResourceName() {
        // GIVEN
        String resouceName = "projects/" + PROJECT +
                "/locations/" + LOCATION +
                "/keyRings/" + KEY_RING +
                "/cryptoKeys/" + CRYPTO_KEY +
                "/cryptoKeyVersions/" + VERSION;

        SignatureAlgorithm signatureAlgorithm = Mockito.mock(SignatureAlgorithm.class);

        // WHEN
        GoogleCloudKeyInfo keyInfo = GoogleCloudKeyInfo.fromResourceName(resouceName, signatureAlgorithm);

        // THEN
        Assert.assertEquals(keyInfo.getProject(), PROJECT);
        Assert.assertEquals(keyInfo.getLocation(), LOCATION);
        Assert.assertEquals(keyInfo.getKeyRing(), KEY_RING);
        Assert.assertEquals(keyInfo.getCryptoKey(), CRYPTO_KEY);
        Assert.assertEquals(keyInfo.getCryptoKeyVersion(), VERSION);
        Assert.assertEquals(keyInfo.getSignatureAlgorithm(), signatureAlgorithm);
    }
}