package com.octo.app.file.crypter;

import com.octo.app.exception.EncryptFileException;
import com.octo.app.file.crypt.encrypt.RsaEncrypter;
import com.octo.app.key.AesKey;
import com.octo.app.key.RsaKey;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.io.File;
import java.security.Key;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class RsaEncrypterTest {

    private static final String RSA_CYPHER_PADDING = "RSA/ECB/PKCS1Padding";

    private SecretKey getAesSecretKey() {
        return new AesKey().getSecretKey();
    }

    private Key createRSAPublicKey() {
        return new RsaKey().getRsaPublicKey();
    }

    /**
     * Test to create RSAEncrypter object with bad arguments.
     */
    @Test
    public void rsaEncrypterCheckArgumentsTest() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new RsaEncrypter(null, null, null))
                .withMessageContaining("Error, impossible to encrypt secret key because it's a null object.");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new RsaEncrypter(getAesSecretKey(), null, null))
                .withMessageContaining("Error, impossible to encrypt object with null aes key.");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new RsaEncrypter(getAesSecretKey(), createRSAPublicKey(), null))
                .withMessageContaining("Error, impossible to encrypt object with null cipher algorithm.");
    }

    /**
     * Test to init cipher with bad arguments.
     */
    @Test
    public void initCipherWithBadArgsTest() {
        assertThatExceptionOfType(EncryptFileException.class)
                .isThrownBy(() -> new RsaEncrypter(getAesSecretKey(), createRSAPublicKey(), ""))
                .withMessageContaining("Error during initialize Cipher object ");
        assertThatExceptionOfType(EncryptFileException.class)
                .isThrownBy(() -> new RsaEncrypter(getAesSecretKey(), createRSAPublicKey(), "TOTO"))
                .withMessageContaining("Error during initialize Cipher object ");
    }

    /**
     * Test to init cipher with good arguments.
     */
    @Test
    public void RsaEncrypterTest() {
        RsaEncrypter rsaEncrypter = new RsaEncrypter(getAesSecretKey(), createRSAPublicKey(), RSA_CYPHER_PADDING);
        File encryptedAesKey = rsaEncrypter.getResultFile();
        Assert.assertNotNull(rsaEncrypter);
        Assert.assertTrue(encryptedAesKey.isFile());
        Assert.assertTrue(encryptedAesKey.length() > 0);
    }
}
