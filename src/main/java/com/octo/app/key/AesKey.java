package com.octo.app.key;


import org.apache.log4j.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
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

