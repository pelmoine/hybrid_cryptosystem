package com.octo.app.file;

import com.octo.app.key.AesKey;
import com.octo.app.key.RsaKey;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.io.File;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class EncrypterTest {
    private static final String FILE_NAME = "fileToEncrypt.txt";
    private static final String RSA_CYPHER_PADDING = "RSA/ECB/PKCS1Padding";

    private File createOriginalFile() {
        return ResourcesFileHelper.getFileFromResources(FILE_NAME);
    }

    private AesKey createAesKey() {
        return new AesKey();
    }

    private RsaKey createRsaKey() {
        return new RsaKey();
    }

    @Test
    public void encryptFileIllegalArgumentExceptionTest() {
        File file = null;
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new Encrypter(file, null, null))
                .withMessageContaining("Error, impossible to encrypt object with null original file.");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new Encrypter(ResourcesFileHelper.getFileFromResources(FILE_NAME), null, null))
                .withMessageContaining("Error, impossible to encrypt object with null aes key.");

        SecretKey key = null;
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new Encrypter(key, null, null))
                .withMessageContaining("Error, impossible to encrypt secret key because it's a null object.");

    }
    @Test
    public void encryptFileTest() {
        Encrypter encrypter = new Encrypter(createOriginalFile(), createAesKey().getSecretKey(), "AES");
        Assert.assertNotNull(encrypter);
        Assert.assertNotNull(encrypter.getEncryptedFile());
        Assert.assertTrue(encrypter.getEncryptedFile().isFile());
        Assert.assertTrue(encrypter.getEncryptedFile().length() > 0);
    }

    @Test
    public void encryptAesKeyTest() {
        Encrypter encrypter = new Encrypter(createAesKey().getSecretKey(), createRsaKey().getRsaPublicKey(), RSA_CYPHER_PADDING);
        Assert.assertNotNull(encrypter);
        Assert.assertNotNull(encrypter.getEncryptedFile());
        Assert.assertTrue(encrypter.getEncryptedFile().isFile());
        Assert.assertTrue(encrypter.getEncryptedFile().length() > 0);
    }
}
