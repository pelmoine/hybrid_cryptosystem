package com.octo.app;


import com.octo.app.file.Encrypter;
import com.octo.app.file.ResourcesFileHelper;
import com.octo.app.key.AesKey;
import com.octo.app.key.RsaKey;
import org.apache.log4j.Logger;

import javax.crypto.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;


/**
 * Program used to encrypt id files with public/private system key of our app.
 * Our app only have public key which used to encrypt id file and could not decrypt them.
 *
 * The original file won't be stored and private key be keep in safe with autority do use it on demand.
 * Symetrical cryptograph is too resources costly so we used hybrid system work's as follow :
 *
 * 1. Generate a symetrical AES Key (TEMP_AES_KEY)
 * 2. Encrypt file id with TEMP_AES_KEY
 * 3. Encrypt TEMP_AES_KEY with RSA_PUBLIC_KEY (previously generated)
 * 4. Save encrypt file with AES_KEY_ENCRYPTED_BY_RSA
 *
 * @author epelmoine
 */
class App
{
    private static final Logger LOGGER = Logger.getLogger(App.class);

   // private static final String RSA_CYPHER_PADDING = "RSA/ECB/PKCS8Padding";
   private static final String AES_CYPHER_PADDING = "AES";
    private static final String RSA_CYPHER_PADDING = "RSA/ECB/PKCS1Padding";
    private static final String ENCRYPTED_AES_KEY_FILE_NAME = "encryptAesKeyWithRsaPublicKey";
    private static final String NAME_FILE_TO_ENCRYPT = "ebillet.pdf";
    /**
     * Application entry point
     * @param args file name to encrypt, must be present in resource folder.
     */
    public static void main(String[] args) {

        File fileToEncrypt = ResourcesFileHelper.getFileFromResources(NAME_FILE_TO_ENCRYPT);
        // Encrypt file with AES
        AesKey aesKey = new AesKey();
        Encrypter encrypterFile = new Encrypter(fileToEncrypt, aesKey.getSecretKey(), "AES");
        // Encrypt AES with RSA
        RsaKey rsaKey = new RsaKey();
        Encrypter encrypterAes = new Encrypter(aesKey.getSecretKey(), rsaKey.getRsaPublicKey(), RSA_CYPHER_PADDING);
        rsaKey.encryptAesKey(aesKey);

      // Generate Rsa Key
  /*      app.generateRsaKey();

        // Encrypt AES Key with RSA private key
        app.encryptAesKeyWithRsaPublicKey(tempAesKey);*/

    }

    /**
     * Encrypt AES Key with RSA public Key
     * @param
     *//*
    private void encryptAesKeyWithRsaPublicKey(SecretKey tempAesKey) {
        PublicKey rsaPublicKey = this.getRsaPublicKey();
        byte[] encryptAesKeyByte = this.getEncryptAesKeyWithRsaPublicKey(tempAesKey, rsaPublicKey);
        this.writeEncryptedAesKeyByte(encryptAesKeyByte);


    }*/

    private void writeEncryptedAesKeyByte(byte[] encryptAesKeyByte) {
        try (FileOutputStream encryptedAesKeyOutputStream = new FileOutputStream(ENCRYPTED_AES_KEY_FILE_NAME)) {
            this.writeEncryptedAesKeyByteInFile(encryptAesKeyByte, encryptedAesKeyOutputStream);
        } catch (FileNotFoundException e) {
            LOGGER.error("Error when getting encrypted AES key output stream with file name : "  + ENCRYPTED_AES_KEY_FILE_NAME, e);
        } catch (IOException e) {
            LOGGER.error("Error when writing encrypted AES key output stream with file name : "  + ENCRYPTED_AES_KEY_FILE_NAME, e);

        }

    }

    /**
     *
     * @param encryptAesKeyByte encrypted aes key byte.
     * @param encryptedAesKeyOutputStream encrypted aes key output stream.
     */
    private void writeEncryptedAesKeyByteInFile(byte[] encryptAesKeyByte, FileOutputStream encryptedAesKeyOutputStream) {
        try {
            encryptedAesKeyOutputStream.write(encryptAesKeyByte);
        } catch (IOException e) {
            LOGGER.error("Error during writting in encrypted aes key output stream.", e);
            e.printStackTrace();
        }
    }

    /**
     * Get encrypted aes key by rsa public key
     * @param tempAesKey the aes key will be encrypted
     * @param rsaPublicKey the rsa public key used to encrypt aes key.
     * @return the encrypted aes key by rsa public key.
     */
    private byte[] getEncryptAesKeyWithRsaPublicKey(SecretKey tempAesKey, PublicKey rsaPublicKey) {
        final Cipher encryptCipher = this.getCipherRsaPadding();
        this.initCipherEncryptMode(encryptCipher,rsaPublicKey);
        return this.getEncryptAesKeyByte(encryptCipher,tempAesKey);
    }

    /**
     * encrypt aes key with rsa cipher and return it.
     * @param encryptCipher the cipher previously initialized.
     * @param tempAesKey the aes key will be encrypted
     * @return the aes key encrypted with rsa cipher
     */
    private byte[] getEncryptAesKeyByte(Cipher encryptCipher, SecretKey tempAesKey) {
        byte[] encryptAesKeyByte = null;
        try {
            encryptAesKeyByte =  encryptCipher.doFinal(tempAesKey.getEncoded());
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            LOGGER.error("Bad padding used : " + RSA_CYPHER_PADDING + ". " ,e);
        }
        return encryptAesKeyByte;
    }

    /**
     * Initialized the cipher in encrypt mode and the rsa public key.
     * @param encryptCipher the cipher to initialized
     * @param rsaPublicKey the rsa public key
     */
    private void initCipherEncryptMode(Cipher encryptCipher, PublicKey rsaPublicKey) {
        try {
            encryptCipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
        } catch (InvalidKeyException e) {
            LOGGER.error("The given key is inappropriate for this key factory. " , e);
        }
    }

    /**
     * getCipherRsaPadding
     * @return Cipher Cipher
     */
    private Cipher getCipherRsaPadding() {
        Cipher cipher = null;
        try{
            cipher = Cipher.getInstance(RSA_CYPHER_PADDING);
        }catch (NoSuchPaddingException e) {
            LOGGER.error("Padding  is requested but is not available in the environment. " + RSA_CYPHER_PADDING + ". " ,e);
        }catch (NoSuchAlgorithmException e) {
            LOGGER.error("Algorithm not found : " + RSA_CYPHER_PADDING, e);
        }
        return cipher;
    }


    /**
     * Get the rsa public key from the byte array (read from te file previously generated)
     * @param rsaPublicKeyByte the byte array from the file.
     * @return a rsa <PublicKey> object
     *//*
    private PublicKey getRsaPublicKeyFromFileByte(byte[] rsaPublicKeyByte) {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(rsaPublicKeyByte);
        return this.generateRsaPublicKeyFromKeyFactory(keySpec);
    }*/

    /**
     * Generate rsa public key from key factory.
     * @param keySpec An X509 encoded key spec
     * @return
     *//*
    private PublicKey generateRsaPublicKeyFromKeyFactory(X509EncodedKeySpec keySpec) {
        PublicKey rsaPublicKey = null;
        KeyFactory keyFactory =  this.getKeyFactoryFromRsaAlgorithm();
        try {
            rsaPublicKey= keyFactory.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            LOGGER.error("Error during generateRsaPublicKeyFromKeyFactory method. " +
                    "The given key specification is inappropriate for this key factory to produce a public key", e);
        }
        return rsaPublicKey;
    }*/

    /**
     * Get a byte array represented a rsa public key file.
     * @param path the rsa public key file path
     * @return a byte array represented a rsa public key file.
     */
    private byte[] getRsaPublicKeyByte(Path path) {
        byte[] rsaPublicKeyByte = null;
        try {
            rsaPublicKeyByte = Files.readAllBytes(path);
        } catch (IOException e) {
            LOGGER.error("Error during getting rsa public key from path : " + path, e);
        }
        return rsaPublicKeyByte;
    }


}
