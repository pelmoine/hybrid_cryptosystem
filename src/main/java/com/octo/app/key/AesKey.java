package com.octo.app.key;


import org.apache.log4j.Logger;

import javax.crypto.*;
import java.security.*;

/**

 *
 * @author epelmoine
 */
public class AesKey {

    /** LOGGER **/
    private static final Logger LOGGER = Logger.getLogger(AesKey.class);
    /** AES ALGORITHME NAME **/
    private static final String AES_ALGORITHM_NAME = "AES";
    /** secretKey Object **/
    private SecretKey secretKey;

    public AesKey() {
        secretKey = initAesSecretKey();
    }
    /**
     * Create AES Key
     *
     * @return SecretKey the secret AES key
     */
    private static SecretKey initAesSecretKey() {
        SecretKey secretKey = null;
        try {
            KeyGenerator keyGen;
            keyGen = KeyGenerator.getInstance(AES_ALGORITHM_NAME);
            keyGen.init(new SecureRandom());
            secretKey =  keyGen.generateKey();
        } catch (final NoSuchAlgorithmException e) {
            LOGGER.error(String.format("Error, during init AES Secret key %S algorithm do not exist.",AES_ALGORITHM_NAME),e);
        }
        return secretKey;
    }

    /**
     * Get Sercret Aes Key.
     * @return secret aes key.
     */
    public SecretKey getSecretKey() {
        return secretKey;
    }
}
