package com.octo.app.file;

import org.junit.Test;

import java.io.File;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class EncryptFileTest {
    private static final String FILE_NAME = "ebillet.pdf";

    @Test
    public void encryptFileIllegalArgumentExceptionTest() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new EncryptFile(null, null))
                .withMessageContaining("Error, impossible to create Encrypt file object with null original file.");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new EncryptFile(RessourcesFileHelper.getFileFromResources(FILE_NAME), null))
                .withMessageContaining("Error, impossible to create Encrypt file object with null aes key.");

    }
    @Test
    public void encryptFileTest() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new EncryptFile(null, null))
                .withMessageContaining("Error, impossible to create Encrypt file object with null original file.");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new EncryptFile(RessourcesFileHelper.getFileFromResources(FILE_NAME), null))
                .withMessageContaining("Error, impossible to create Encrypt file object with null aes key.");

    }
}
