package com.octo.app.key;

import com.octo.app.exception.KeyException;
import org.apache.log4j.Logger;

import javax.crypto.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Rsa Key Object.
 *
 * @author epelmoine
 */
public class RsaKey implements Key {

    /**
     * LOGGER
     **/
    private static final Logger LOGGER = Logger.getLogger(RsaKey.class);
    private static final String RSA_ALGORITHM_NAME = "RSA";
    private static final String RSA_BASE_FILE_NAME = "rsa";
    private static final String RSA_PUBLIC_KEY_FILE_NAME = RSA_BASE_FILE_NAME + ".pub";
    private static final String RSA_PRIVATE_KEY_FILE_NAME = RSA_BASE_FILE_NAME + ".key";
    private static final String RSA_CYPHER_PADDING = "RSA/ECB/PKCS1Padding";
    private static final String ENCRYPTED_AES_KEY_FILE_NAME = "encryptAesKeyWithRsaPublicKey";
    private PublicKey rsaPublicKey;
    private PrivateKey rsaPrivateKey;

    public RsaKey() {
        generate();
    }

    @Override
    public void generate() {
        File rsaPrivateKeyFile;
        File rsaPublicKeyFile;
        //generate RSA Private/Public Key only if file doesn't exist
        rsaPrivateKeyFile = new File(RSA_PRIVATE_KEY_FILE_NAME);
        rsaPublicKeyFile = new File(RSA_PUBLIC_KEY_FILE_NAME);

        // If one of private/public key not exist, delete both and generate a new pair
        if (rsaPrivateKeyFile.length() <= 0 || rsaPublicKeyFile.length() <= 0) {
            LOGGER.info("File not exist in resources but will be generated.");
            deletePreviousRsaKeyFile(rsaPrivateKeyFile, rsaPublicKeyFile);
            generateNewRsaKeyFile();

        } else {
            loadRsaPrivateKeyFromFile();
            loadRsaPublicKeyFromFile();
        }
    }

    /**
     * delete privious rsa key file (public and private)
     *
     * @param rsaPrivateKeyFile rsa private key file
     * @param rsaPublicKeyFile  rsa public key file
     */
    private void deletePreviousRsaKeyFile(File rsaPrivateKeyFile, File rsaPublicKeyFile) {
        deleteFile(rsaPrivateKeyFile);
        deleteFile(rsaPublicKeyFile);
    }

    private void deleteFile(File file) {
        try {
            Files.delete(file.toPath());
        } catch (IOException e) {
            throw new KeyException(String.format("Error during the deleting of %s file.", file.getName()), e);
        }
        LOGGER.info(String.format("%s file has been correctly deleted.", file.getName()));
    }

    private void generateNewRsaKeyFile() {
        KeyPair kp = generateRsaKeyPair();
        generateRsaPublicKeyFile(kp);
        generateRsaPrivateKeyFile(kp);
    }

    /**
     * Generate rsa public key file.
     *
     * @param kp the KeyPair used to generate rsa public/private key file.
     */
    private void generateRsaPublicKeyFile(KeyPair kp) {
        rsaPublicKey = kp.getPublic();
        generateFileOutputStream(RSA_PUBLIC_KEY_FILE_NAME, rsaPublicKey.getEncoded());
        LOGGER.info("Public key format: " + rsaPublicKey.getFormat());
    }

    /**
     * Generate rsa private key file.
     *
     * @param kp the KeyPair used to generate rsa public/private key file.
     */
    private void generateRsaPrivateKeyFile(KeyPair kp) {
        rsaPrivateKey = kp.getPrivate();
        generateFileOutputStream(RSA_PRIVATE_KEY_FILE_NAME, rsaPrivateKey.getEncoded());
        LOGGER.info("Private key format: " + rsaPrivateKey.getFormat());
    }


    /**
     * @param nameFile the name file.
     * @param content  the content.
     */
    private void generateFileOutputStream(String nameFile, byte[] content) {
        try (OutputStream out = new FileOutputStream(nameFile)) {
            out.write(content);
        } catch (IOException iOException) {
            LOGGER.error("Cannot write key file : ", iOException);
        }
    }

    /**
     * Generate rsa key pair.
     * It will be used to generate rsa public and private key file.
     *
     * @return a rsa KeyPair object to generate rsa public and private key file.
     */
    private KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA_ALGORITHM_NAME);
            kpg.initialize(2048);
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new KeyException("Generate rsa key pair, RSA algorithm do not exist : ", e);
        }
    }

    public void encryptAesKey(AesKey aesKey) {
        byte[] encryptAesKeyByte = getEncryptAesKeyByte(aesKey.getSecretKey());
        writeEncryptedAesKeyByte(encryptAesKeyByte);
    }

    private void writeEncryptedAesKeyByte(byte[] encryptAesKeyByte) {
        try (FileOutputStream encryptedAesKeyOutputStream = new FileOutputStream(ENCRYPTED_AES_KEY_FILE_NAME)) {
            encryptedAesKeyOutputStream.write(encryptAesKeyByte);
        } catch (FileNotFoundException e) {
            LOGGER.error("Error when getting encrypted AES key output stream with file name : " + ENCRYPTED_AES_KEY_FILE_NAME, e);
        } catch (IOException e) {
            LOGGER.error("Error when writing encrypted AES key output stream with file name : " + ENCRYPTED_AES_KEY_FILE_NAME, e);
        }
    }


    /**
     * getCipherRsaPadding
     *
     * @return Cipher Cipher
     */
    private Cipher getCipherRsaPadding() {
        try {
            Cipher cipher = Cipher.getInstance(RSA_CYPHER_PADDING);
            initCipherEncryptMode(cipher);
            return cipher;
        } catch (NoSuchPaddingException e) {
            throw new KeyException("Padding  is requested but is not available in the environment. " + RSA_CYPHER_PADDING + ". ", e);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyException("Algorithm not found : " + RSA_CYPHER_PADDING, e);
        }

    }

    /**
     * Initialized the cipher in encrypt mode and the rsa public key.
     *
     * @param encryptCipher the cipher to initialized
     */
    private void initCipherEncryptMode(Cipher encryptCipher) {
        try {
            encryptCipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
        } catch (InvalidKeyException e) {
            LOGGER.error("The given key is inappropriate for this key factory. ", e);
        }
    }

    /**
     * encrypt aes key with rsa cipher and return it.
     *
     * @param tempAesKey the aes key will be encrypted
     * @return the aes key encrypted with rsa cipher
     */
    private byte[] getEncryptAesKeyByte(SecretKey tempAesKey) {
        final Cipher cipher = getCipherRsaPadding();
        byte[] encryptAesKeyByte = null;
        try {
            encryptAesKeyByte = cipher.doFinal(tempAesKey.getEncoded());
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            LOGGER.error("Bad padding used : " + RSA_CYPHER_PADDING + ". ", e);
        }
        return encryptAesKeyByte;
    }


    /**
     * Get Rsa Private Key.
     *
     * @return The rsa Private KEy
     */
    public PrivateKey getRsaPrivateKey() {
        return rsaPrivateKey;
    }

    /**
     * Get Rsa public Key.
     *
     * @return The rsa Private KEy
     */
    public PublicKey getRsaPublicKey() {
        return rsaPublicKey;
    }

    /**
     * load the rsa private key from file.
     */
    private void loadRsaPrivateKeyFromFile() {
        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(RSA_PRIVATE_KEY_FILE_NAME));
            PKCS8EncodedKeySpec spec =
                    new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            rsaPrivateKey = kf.generatePrivate(spec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            LOGGER.error("Error during loading the rsa private key. ", e);
        }
    }

    /**
     * Load the rsa public key from file.
     */
    private void loadRsaPublicKeyFromFile() {
        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(RSA_PUBLIC_KEY_FILE_NAME));
            X509EncodedKeySpec spec =
                    new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            rsaPublicKey = kf.generatePublic(spec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            LOGGER.error("Error during loading the rsa public key. ", e);
        }
    }

}
