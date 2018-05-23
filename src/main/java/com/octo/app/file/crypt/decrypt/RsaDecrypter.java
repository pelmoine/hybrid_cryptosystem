package com.octo.app.file.crypt.decrypt;

import com.octo.app.file.ResourcesFileHelper;
import com.octo.app.file.crypt.AbstractEncrypter;

import javax.crypto.Cipher;
import java.io.File;
import java.security.Key;
import java.security.PrivateKey;

public class RsaDecrypter extends AbstractEncrypter {

    private Cipher cipher;

    /**
     * Rsa Decrypter Constructor.
     *
     * @param fileToDecrypt    the file to decrypt.
     * @param rsaPrivateKey    the rsa private key used to decrypt the file.
     * @param rsaCypherPadding the rsa cypher padding used to init cypher.
     */
    public RsaDecrypter(File fileToDecrypt, PrivateKey rsaPrivateKey, String rsaCypherPadding) {
        checkArguments(fileToDecrypt, rsaPrivateKey, rsaCypherPadding);
        initCipher(rsaPrivateKey, rsaCypherPadding, Cipher.DECRYPT_MODE);
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
     * Decrypt aes secret key and write it in a file.
     *
     * @param fileToDecrypt the file to decrypt.
     */
    private void decrypt(File fileToDecrypt) {
        resultFile = new File("aes_key_encrypted.key");
        byte[] inputBytes = ResourcesFileHelper.getFileByte(fileToDecrypt);
        byte[] outputBytes = getBytesFromCipher(inputBytes);
        writeByteInFile(outputBytes, resultFile);
    }
}
