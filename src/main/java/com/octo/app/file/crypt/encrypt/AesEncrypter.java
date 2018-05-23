package com.octo.app.file.crypt.encrypt;

import com.octo.app.file.ResourcesFileHelper;
import com.octo.app.file.crypt.AbstractEncrypter;
import org.apache.log4j.Logger;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.File;
import java.security.Key;

public class AesEncrypter extends AbstractEncrypter {

    private static final Logger LOGGER = Logger.getLogger(AesEncrypter.class);

    /**
     * Main constructor
     *
     * @param originalFile    the original file
     * @param key             the secret key
     * @param cipherAlgorithm the cipher algorithm
     */
    public AesEncrypter(File originalFile, SecretKey key, String cipherAlgorithm) {
        checkArguments(originalFile, key, cipherAlgorithm);
        initCipher(key, cipherAlgorithm, Cipher.ENCRYPT_MODE);
        encrypt(originalFile);
    }

    /**
     * Check arguments : original file, key and cipher algorithm.
     *
     * @param originalFile    the original file.
     * @param key             the key.
     * @param cipherAlgorithm the cipher algorithm.
     */
    private void checkArguments(File originalFile, Key key, String cipherAlgorithm) {
        if (originalFile == null) {
            throw new IllegalArgumentException("Error, impossible to encrypt object with null original file.");
        }
        checkArguments(key, cipherAlgorithm);
    }


    /**
     * Create encrypted file from original file name.
     *
     * @param originalFileName original file name.
     * @return an empty file.
     */
    private File createEmptyEncryptedFile(String originalFileName) {
        String encryptedFileName = ResourcesFileHelper.createEncryptedFileName(originalFileName);
        return new File(encryptedFileName);
    }

    /**
     * Encrypte original file and write  it in the encrypt file.
     *
     * @param originalFile original file.
     */
    private void encrypt(File originalFile) {
        resultFile = createEmptyEncryptedFile(originalFile.getName());
        byte[] inputBytes = ResourcesFileHelper.getFileByte(originalFile);
        byte[] outputBytes = getBytesFromCipher(inputBytes);
        writeByteInFile(outputBytes, resultFile);
    }



}
