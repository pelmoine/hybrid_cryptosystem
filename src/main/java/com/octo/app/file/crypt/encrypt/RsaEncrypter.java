package com.octo.app.file.crypt.encrypt;

import com.octo.app.file.crypt.AbstractEncrypter;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.File;
import java.security.Key;

public class RsaEncrypter extends AbstractEncrypter {

    /**
     * Constructor Encrypter for encrypt key
     *
     * @param secretKey       the secret key to encrypt
     * @param rsaPrivateKey   the rsa private key used to encrypt
     * @param cipherAlgorithm the cipher algorithm
     */
    public RsaEncrypter(SecretKey secretKey, Key rsaPrivateKey, String cipherAlgorithm) {
        checkArguments(secretKey, rsaPrivateKey, cipherAlgorithm);
        initCipher(rsaPrivateKey, cipherAlgorithm, Cipher.ENCRYPT_MODE);
        encrypt(secretKey);
    }

    /**
     * Check the arguments : secret key, key and cipher algorithm.
     *
     * @param secretKey       the secret key.
     * @param key             the key.
     * @param cipherAlgorithm the cipher algorithm.
     */
    private void checkArguments(SecretKey secretKey, Key key, String cipherAlgorithm) {
        if (secretKey == null) {
            throw new IllegalArgumentException("Error, impossible to encrypt secret key because it's a null object.");
        }
        checkArguments(key, cipherAlgorithm);
    }


    /**
     * Encrypt secret key and write it in the encrypt file.
     *
     * @param secretKey   the secret key to encrypt.
     */
    private void encrypt(SecretKey secretKey) {
        resultFile = new File("aes_key_encrypted.key");
        byte[] inputBytes = secretKey.getEncoded();
        byte[] outputBytes = getBytesFromCipher(inputBytes);
        writeByteInFile(outputBytes, resultFile);
    }
}
