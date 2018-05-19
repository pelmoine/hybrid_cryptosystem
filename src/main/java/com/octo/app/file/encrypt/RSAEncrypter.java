package com.octo.app.file.encrypt;

import com.octo.app.exception.EncryptFileException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.File;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class RSAEncrypter extends AbstractEncrypter {

    /**
     * Constructor Encrypter for encrypt key
     *
     * @param secretKey       the secret key to encrypt
     * @param rsaPrivateKey   the rsa private key used to encrypt
     * @param cipherAlgorithm the cipher algorithm
     */
    public RSAEncrypter(SecretKey secretKey, PublicKey rsaPrivateKey, String cipherAlgorithm) {
        checkArguments(secretKey, rsaPrivateKey, cipherAlgorithm);
        initCipher(rsaPrivateKey, cipherAlgorithm);
        setEncryptedFile(new File("aes_key_encrypted.key"));
        encrypt(secretKey, getEncryptedFile());
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
     * Initialized the cipher.
     *
     * @param key private key  key
     */
    private void initCipher(PublicKey key, String cipherAlgorithm) {
        try {
            setCipher(Cipher.getInstance(cipherAlgorithm));
            getCipher().init(Cipher.ENCRYPT_MODE, key);
        } catch (final NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException e) {
            throw new EncryptFileException("Error during initialize Cipher object : ", e);
        }
    }

    /**
     * Encrypt secret key and write it in the encrypt file.
     *
     * @param secretKey   the secret key to encrypt.
     * @param encryptFile the encrypted file.
     */
    private void encrypt(SecretKey secretKey, File encryptFile) {
        byte[] inputBytes = secretKey.getEncoded();
        byte[] outputBytes = getEncryptedBytes(inputBytes);
        writeEncryptedFile(outputBytes, encryptFile);
    }
}
