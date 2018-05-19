package com.octo.app.file.encrypt;

import com.octo.app.exception.EncryptFileException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;

abstract class AbstractEncrypter {

    private File encryptedFile;
    private Cipher cipher;

    /**
     * Check arguments key and cipher algorithm
     *
     * @param key             the key
     * @param cipherAlgorithm the cipher algorithm
     */
    void checkArguments(Key key, String cipherAlgorithm) {
        if (key == null) {
            throw new IllegalArgumentException("Error, impossible to encrypt object with null aes key.");
        }
        if (cipherAlgorithm == null) {
            throw new IllegalArgumentException("Error, impossible to encrypt object with null cipher algorithm.");
        }
    }

    /**
     * Get encrypted Bytes
     *
     * @param inputBytes the input byte not encrypted yet.
     * @return the encrypted bytes.
     */
    byte[] getEncryptedBytes(byte[] inputBytes) {
        try {
            return cipher.doFinal(inputBytes);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptFileException("Error during getting encrypted bytes from the input bytes.\n", e);
        }
    }

    /**
     * Write the output byte in the encrypted file.
     *
     * @param outputBytes output bytes.
     * @param encryptFile encrypted file.
     */
    void writeEncryptedFile(byte[] outputBytes, File encryptFile) {
        try (FileOutputStream outputStream = new FileOutputStream(encryptFile)) {
            outputStream.write(outputBytes);
        } catch (IOException e) {
            throw new EncryptFileException("Error during writting ecrypted file.\n", e);
        }
    }

    /**
     * Get encrypted file.
     *
     * @return encrypted file.
     */
    File getEncryptedFile() {
        return encryptedFile;
    }

    /**
     * set encrypted file.
     *
     * @param encryptedFile file.
     */
    void setEncryptedFile(File encryptedFile) {
        this.encryptedFile = encryptedFile;
    }

    /**
     * Get Cipher.
     *
     * @return cipher the cipher.
     */
    Cipher getCipher() {
        return cipher;
    }

    /**
     * Set Cipher.
     *
     * @param cipher the cipher.
     */
    void setCipher(Cipher cipher) {
        this.cipher = cipher;
    }
}
