package com.octo.app.file.crypt;

import com.octo.app.exception.EncryptFileException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public abstract class AbstractEncrypter {

    protected File resultFile;
    private Cipher cipher;

    /**
     * Check arguments key and cipher algorithm
     *
     * @param key             the key
     * @param cipherAlgorithm the cipher algorithm
     */
    protected void checkArguments(Key key, String cipherAlgorithm) {
        if (key == null) {
            throw new IllegalArgumentException("Error, impossible to encrypt object with null aes key.");
        }
        if (cipherAlgorithm == null) {
            throw new IllegalArgumentException("Error, impossible to encrypt object with null cipher algorithm.");
        }
    }

    /**
     * Initialized the cipher.
     *
     * @param key secret key
     */
    protected void initCipher(Key key, String cipherAlgorithm, int cipherMode) {
        try {
            setCipher(Cipher.getInstance(cipherAlgorithm));
            getCipher().init(cipherMode, key);
        } catch (final NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException e) {
            throw new EncryptFileException(String.format("Error during initialize Cipher object with cipher algorithm %s.", cipherAlgorithm), e);
        }
    }

    /**
     * Get encrypted Bytes
     *
     * @param inputBytes the input byte not encrypted yet.
     * @return the encrypted bytes.
     */
    protected byte[] getBytesFromCipher(byte[] inputBytes) {
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
     * @param file encrypted file.
     */
    protected void writeByteInFile(byte[] outputBytes, File file) {
        try (FileOutputStream outputStream = new FileOutputStream(file)) {
            outputStream.write(outputBytes);
        } catch (IOException e) {
            throw new EncryptFileException("Error during writting ecrypted file.\n", e);
        }
    }

    public File getResultFile() {
        return resultFile;
    }
    /**
     * Get Cipher.
     *
     * @return cipher the cipher.
     */
    private Cipher getCipher() {
        return cipher;
    }

    /**
     * Set Cipher.
     *
     * @param cipher the cipher.
     */
    private void setCipher(Cipher cipher) {
        this.cipher = cipher;
    }
}
