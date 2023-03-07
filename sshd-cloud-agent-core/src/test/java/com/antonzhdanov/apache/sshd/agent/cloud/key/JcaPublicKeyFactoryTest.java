package com.antonzhdanov.apache.sshd.agent.cloud.key;

import org.apache.sshd.common.cipher.ECCurves;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.testng.Assert.assertNotNull;

@Test
public class JcaPublicKeyFactoryTest {

    static final String EC_PUBLIC_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYNa3ZyxdY6OyWsh436rrNsL+IvJjoXbEb3IwCAfRIUPzj0ZvL06QPtX6VPpcoilrcsLKluvsy1f0Z7IiDl469A==";
    static final String RSA_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3iVnztZ6BNt72/sYlNTQSTn+vXF9X88tyngNSS3TvnQd9PBelffCQf1ELGHyPepRgyNEgsTEwoJqLJfZM+8E3l4d0WdXfXWEsFZTprheQ3m+CqScGfmvBJKLIaWflv2Pk5c0Zx+/GiTtxWPczclFZIccBeJJlzxbBSG4KGKCjSUfjsRC84Dy8E4/gUiwk+Ffe2RwIBcsUC6Byi+vEHoCNQMgvBHPYnJsvMyveae5SeGFP7RsK3FAoTYGVjpxOBnYDsW8gOI/TuvxLZiK97SrXHGJOS+IVyBC1hQEUZ/er4wQUZ7g6Fw+ulbYXJ4ZWvCsDe6aPYNSsYIl7vFAdLVMNQIDAQAB";

    static final String RSA_PUBLIC_KEY_MODULUS = "28043349041905478952326161687290951601816801907622698258735465566988500248048984209000022685060540062842813645738580522316374914945717046549095873986635542811516223132421467201417347546410265450633948036686956551600245373072150509156499112291637979339983970191845473136048501618392331148567586654455316386870058346861918315126904244155372739928741790697680934566610439012657137423677564667014171974529145822398684971336289678214005185944583960435701425830722674416204724836631927686557572670662622243270083959634673573034139391620037502291570844360392918563468805113133271274452137563642489610410078956618038423931957";
    static final String RSA_PUBLIC_KEY_EXPONENT = "65537";

    static final String EC_PUBLIC_KEY_X = "43801404536984275848840385811041406551069557149408309779838004442058393198915";
    static final String EC_PUBLIC_KEY_Y = "110165167455777393567829674131101241750836358335358364354663905856202056022772";

    @DataProvider
    public Object[][] byteArrayPublicKeyProvider() {
        return new Object[][] {
                {Base64.getDecoder().decode(EC_PUBLIC_KEY), ECPublicKey.class},
                {Base64.getDecoder().decode(RSA_PUBLIC_KEY), RSAPublicKey.class}
        };
    }

    @DataProvider
    public Object[][] pemPublicKeyProvider() {
        return new Object[][] {
                {"-----BEGIN PUBLIC KEY-----\n" + EC_PUBLIC_KEY + "\n-----END PUBLIC KEY-----", ECPublicKey.class},
                {"-----BEGIN PUBLIC KEY-----\n" + RSA_PUBLIC_KEY + "\n-----END PUBLIC KEY-----", RSAPublicKey.class}
        };
    }

    @Test(dataProvider = "byteArrayPublicKeyProvider")
    public void testCreateFromByteArraySuccess(byte[] encoded, Class<PublicKey> instance) {
        // GIVEN
        JcaPublicKeyFactory jcaPublicKeyFactory = new JcaPublicKeyFactory();

        // WHEN
        PublicKey publicKey = jcaPublicKeyFactory.create(encoded);

        // THEN
        Assert.assertTrue(instance.isAssignableFrom(publicKey.getClass()));
    }

    @Test(dataProvider = "pemPublicKeyProvider")
    public void testCreateFromPemSuccess(String pem, Class<PublicKey> instance) {
        // GIVEN
        JcaPublicKeyFactory jcaPublicKeyFactory = new JcaPublicKeyFactory();

        // WHEN
        PublicKey publicKey = jcaPublicKeyFactory.create(pem);

        // THEN
        Assert.assertTrue(instance.isAssignableFrom(publicKey.getClass()));
    }

    public void testCreateRsaKeySuccess() {
        // GIVEN
        JcaPublicKeyFactory jcaPublicKeyFactory = new JcaPublicKeyFactory();


        BigInteger modulus = new BigInteger(RSA_PUBLIC_KEY_MODULUS);
        BigInteger publicExponent = new BigInteger(RSA_PUBLIC_KEY_EXPONENT);

        // WHEN
        RSAPublicKey rsaPublicKey = jcaPublicKeyFactory.create(modulus, publicExponent);

        // THEN
        assertNotNull(rsaPublicKey);
    }

    public void testCreateEcKeySuccess() {
        // GIVEN
        JcaPublicKeyFactory jcaPublicKeyFactory = new JcaPublicKeyFactory();
        BigInteger x = new BigInteger(EC_PUBLIC_KEY_X);
        BigInteger y = new BigInteger(EC_PUBLIC_KEY_Y);
        ECCurves ecCurve = ECCurves.nistp256;

        // WHEN
        ECPublicKey ecPublicKey = jcaPublicKeyFactory.create(x, y, ecCurve);

        // THEN
        assertNotNull(ecPublicKey);
    }
}
