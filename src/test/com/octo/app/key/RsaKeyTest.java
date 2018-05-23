package com.octo.app.key;

import org.junit.Assert;
import org.junit.Test;

import java.security.PrivateKey;
import java.security.PublicKey;

public class RsaKeyTest {
    private static final String RSA_ALGORITHM_NAME = "RSA";

    /**
     * Test simple creation.
     */
    @Test
    public void RsaKeyTest() {
        RsaKey rsaKey = new RsaKey();
        Assert.assertNotNull(rsaKey);
    }

    /**
     * Test rsa public key.
     */
    @Test
    public void getRsaPublicKeyTest() {
        RsaKey rsaKey = new RsaKey();
        PublicKey publicKey = rsaKey.getRsaPublicKey();
        Assert.assertNotNull(publicKey);
        Assert.assertEquals(RSA_ALGORITHM_NAME, publicKey.getAlgorithm());
    }

    /**
     * Test rsa private key.
     */
    @Test
    public void getRsaPrivateKeyTest() {
        RsaKey rsaKey = new RsaKey();
        PrivateKey privateKey = rsaKey.getRsaPrivateKey();
        Assert.assertNotNull(privateKey);
        Assert.assertEquals(RSA_ALGORITHM_NAME, privateKey.getAlgorithm());
    }
}
