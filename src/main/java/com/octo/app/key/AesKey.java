package com.octo.app.key;


import com.octo.app.exception.KeyException;
import org.apache.log4j.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Aes Key Object.
 *
 * @author epelmoine
 */
public class AesKey implements Key {

    /** LOGGER **/
    private static final Logger LOGGER = Logger.getLogger(AesKey.class);
    /** AES ALGORITHME NAME **/
    private static final String AES_ALGORITHM_NAME = "AES";
    /** secretKey Object **/
    private SecretKey secretKey;

    /**
     * Create an aes key.
     */
    public AesKey() {
        generate();
    }

    public AesKey(File resultFile) {
        try {
            byte[] data = Files.readAllBytes(Paths.get(resultFile.getPath()));
            secretKey = new SecretKeySpec(data, "AES");
        } catch (IOException e) {
            throw new KeyException("Error during reading aes file decrypted to transform it in secret key.");
        }
    }

    @Override
    public void generate() {
        try {
            KeyGenerator keyGen;
            keyGen = KeyGenerator.getInstance(AES_ALGORITHM_NAME);
            keyGen.init(new SecureRandom());
            secretKey =  keyGen.generateKey();
        } catch (final NoSuchAlgorithmException e) {
            LOGGER.error(String.format("Error, during init AES Secret key %S algorithm do not exist.",AES_ALGORITHM_NAME),e);
        }
    }

    /**
     * Get Sercret Aes Key.
     * @return secret aes key.
     */
    public SecretKey getSecretKey() {
        return secretKey;
    }


}

