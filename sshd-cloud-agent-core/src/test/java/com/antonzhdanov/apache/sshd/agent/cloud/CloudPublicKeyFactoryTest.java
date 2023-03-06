package com.antonzhdanov.apache.sshd.agent.cloud;

import com.antonzhdanov.apache.sshd.agent.cloud.key.CloudPublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.key.EcCloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.key.PublicKeyFactory;
import com.antonzhdanov.apache.sshd.agent.cloud.key.RsaCloudPublicKey;
import com.antonzhdanov.apache.sshd.agent.cloud.key.TestCloudKeyInfo;
import org.apache.sshd.common.cipher.ECCurves;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class CloudPublicKeyFactoryTest {

    private static final TestCloudKeyInfo KEY_INFO = new TestCloudKeyInfo("ID");

    @DataProvider
    public Object[][] keyProvider() {
        return new Object[][]{
                {mock(ECPublicKey.class), EcCloudPublicKey.class},
                {mock(RSAPublicKey.class), RsaCloudPublicKey.class}
        };
    }

    @Test(dataProvider = "keyProvider")
    public void testCreateFromPem(PublicKey publicKey, Class<PublicKey> instanceOf) {
        // GIVEN
        PublicKeyFactory publicKeyFactory = mock(PublicKeyFactory.class);
        CloudPublicKeyFactory<TestCloudKeyInfo> cloudPublicKeyFactory = new CloudPublicKeyFactory<>(publicKeyFactory);

        String pem = "PEM";
        when(publicKeyFactory.create(eq(pem))).thenReturn(publicKey);

        // WHEN
        CloudPublicKey<TestCloudKeyInfo, PublicKey> cloudPublicKey = cloudPublicKeyFactory.create(pem, KEY_INFO);

        // THEN
        assertTrue(instanceOf.isAssignableFrom(cloudPublicKey.getClass()));
        assertEquals(cloudPublicKey.getCloudKeyInfo(), KEY_INFO);
        assertEquals(cloudPublicKey.getPublicKey(), publicKey);
        verify(publicKeyFactory, times(1)).create(eq(pem));
        verifyNoMoreInteractions(publicKeyFactory);
    }

    @Test(dataProvider = "keyProvider")
    public void testCreateFromBytes(PublicKey publicKey, Class<PublicKey> instanceOf) {
        // GIVEN
        PublicKeyFactory publicKeyFactory = mock(PublicKeyFactory.class);
        CloudPublicKeyFactory<TestCloudKeyInfo> cloudPublicKeyFactory = new CloudPublicKeyFactory<>(publicKeyFactory);

        byte[] bytes = new byte[0];
        when(publicKeyFactory.create(eq(bytes))).thenReturn(publicKey);

        // WHEN
        CloudPublicKey<TestCloudKeyInfo, PublicKey> cloudPublicKey = cloudPublicKeyFactory.create(bytes, KEY_INFO);

        // THEN
        assertTrue(instanceOf.isAssignableFrom(cloudPublicKey.getClass()));
        assertEquals(cloudPublicKey.getCloudKeyInfo(), KEY_INFO);
        assertEquals(cloudPublicKey.getPublicKey(), publicKey);
        verify(publicKeyFactory, times(1)).create(eq(bytes));
        verifyNoMoreInteractions(publicKeyFactory);
    }

    @Test
    public void testCreateFromRsaParams() {
        // GIVEN
        PublicKeyFactory publicKeyFactory = mock(PublicKeyFactory.class);
        CloudPublicKeyFactory<TestCloudKeyInfo> cloudPublicKeyFactory = new CloudPublicKeyFactory<>(publicKeyFactory);

        BigInteger modulus = BigInteger.ONE;
        BigInteger exponent = BigInteger.TWO;
        RSAPublicKey publicKey = mock(RSAPublicKey.class);
        when(publicKeyFactory.create(eq(modulus), eq(exponent))).thenReturn(publicKey);

        // WHEN
        CloudPublicKey<TestCloudKeyInfo, PublicKey> cloudPublicKey = cloudPublicKeyFactory.create(modulus, exponent, KEY_INFO);

        // THEN
        assertTrue(cloudPublicKey instanceof RsaCloudPublicKey);
        assertEquals(cloudPublicKey.getCloudKeyInfo(), KEY_INFO);
        assertEquals(cloudPublicKey.getPublicKey(), publicKey);
        verify(publicKeyFactory, times(1)).create(eq(modulus), eq(exponent));
        verifyNoMoreInteractions(publicKeyFactory);
    }

    @Test
    public void testCreateFromEcParams() {
        // GIVEN
        PublicKeyFactory publicKeyFactory = mock(PublicKeyFactory.class);
        CloudPublicKeyFactory<TestCloudKeyInfo> cloudPublicKeyFactory = new CloudPublicKeyFactory<>(publicKeyFactory);

        BigInteger x = BigInteger.ONE;
        BigInteger y = BigInteger.TWO;
        ECCurves ecCurve = ECCurves.nistp256;
        ECPublicKey publicKey = mock(ECPublicKey.class);
        when(publicKeyFactory.create(eq(x), eq(y), eq(ecCurve))).thenReturn(publicKey);

        // WHEN
        CloudPublicKey<TestCloudKeyInfo, PublicKey> cloudPublicKey = cloudPublicKeyFactory.create(x, y, ecCurve, KEY_INFO);

        // THEN
        assertTrue(cloudPublicKey instanceof ECPublicKey);
        assertEquals(cloudPublicKey.getCloudKeyInfo(), KEY_INFO);
        assertEquals(cloudPublicKey.getPublicKey(), publicKey);
        verify(publicKeyFactory, times(1)).create(eq(x), eq(y), eq(ecCurve));
        verifyNoMoreInteractions(publicKeyFactory);
    }
}