package com.octo.app.file.crypter;

import com.octo.app.exception.EncryptFileException;
import com.octo.app.file.ResourcesFileHelper;
import com.octo.app.file.encrypt.FileEncrypter;
import com.octo.app.key.AesKey;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.io.File;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class FileEncrypterTest {

    private static final String FILE_NAME = "fileToEncrypt.txt";
    private static final String AES_CYPHER_PADDING = "AES";

    private File createOriginalFile() {
        return ResourcesFileHelper.getFileFromResources(FILE_NAME);
    }

    private SecretKey createAes() {
        return new AesKey().getSecretKey();
    }

    /**
     * Test to create FileEncrypter object with bad arguments.
     */
    @Test
    public void fileEncrypterCheckArgumentsTest() {

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new FileEncrypter(null, null, null))
                .withMessageContaining("Error, impossible to encrypt object with null original file.");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new FileEncrypter(createOriginalFile(), null, null))
                .withMessageContaining("Error, impossible to encrypt object with null aes key.");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new FileEncrypter(createOriginalFile(), createAes(), null))
                .withMessageContaining("Error, impossible to encrypt object with null cipher algorithm.");
    }

    /**
     * Test to init cipher with bad arguments.
     */
    @Test
    public void initWithBadCipherTest() {
        assertThatExceptionOfType(EncryptFileException.class)
                .isThrownBy(() -> new FileEncrypter(createOriginalFile(), createAes(), ""))
                .withMessageContaining("Error during initialize Cipher object ");
        assertThatExceptionOfType(EncryptFileException.class)
                .isThrownBy(() -> new FileEncrypter(createOriginalFile(), createAes(), "TOTO"))
                .withMessageContaining("Error during initialize Cipher object ");
    }

    /**
     * Test to init cipher with good arguments.
     */
    @Test
    public void fileEncrypterTest() {
        FileEncrypter fileEncrypter = new FileEncrypter(createOriginalFile(), createAes(), AES_CYPHER_PADDING);
        File encryptedFile = fileEncrypter.getEncryptedFile();
        Assert.assertNotNull(encryptedFile);
        Assert.assertTrue(encryptedFile.isFile());
        Assert.assertTrue(encryptedFile.length() > 0);
    }
}
