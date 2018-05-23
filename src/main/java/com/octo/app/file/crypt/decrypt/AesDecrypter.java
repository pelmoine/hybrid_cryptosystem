package com.octo.app.file.crypt.decrypt;

import com.octo.app.file.ResourcesFileHelper;
import com.octo.app.file.crypt.AbstractEncrypter;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.File;
import java.security.Key;

public class AesDecrypter extends AbstractEncrypter {

    /**
     * Aes decrypter constructor
     *
     * @param fileToDecrypt    the file to decrypt
     * @param secretKey        the secret key to decrypt
     * @param aesCipherPadding the cipher padding
     */
    public AesDecrypter(File fileToDecrypt, SecretKey secretKey, String aesCipherPadding) {
        checkArguments(fileToDecrypt, secretKey, aesCipherPadding);
        initCipher(secretKey, aesCipherPadding, Cipher.DECRYPT_MODE);
        decrypt(fileToDecrypt);
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
     * Derypt
     */
    private void decrypt(File fileToDecrypt) {

        resultFile = new File(ResourcesFileHelper.createDecryptedFileName(fileToDecrypt.getName()));
        byte[] inputBytes = ResourcesFileHelper.getFileByte(fileToDecrypt);
        byte[] outputBytes = getBytesFromCipher(inputBytes);
        writeByteInFile(outputBytes, resultFile);
    }

}
