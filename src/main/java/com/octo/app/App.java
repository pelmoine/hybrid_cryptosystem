package com.octo.app;


import com.octo.app.file.EncryptFile;
import com.octo.app.file.RessourcesFileHelper;
import com.octo.app.key.AesKey;
import org.apache.log4j.Logger;

import javax.crypto.*;
import java.io.*;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Optional;

import static java.util.Optional.ofNullable;


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
public class App 
{
    private static final Logger LOGGER = Logger.getLogger(App.class);
    private static final String RSA_ALGORITHM_NAME = "RSA";
    private static final String RSA_BASE_FILE_NAME = "rsa";
    private static final String RSA_PUBLIC_KEY_FILE_NAME = RSA_BASE_FILE_NAME +".pub";
    private static final String RSA_PRIVATE_KEY_FILE_NAME = RSA_BASE_FILE_NAME +".key";
   // private static final String RSA_CYPHER_PADDING = "RSA/ECB/PKCS8Padding";
    private static final String RSA_CYPHER_PADDING = "RSA/ECB/PKCS1Padding";
    private static final String ENCRYPTED_AES_KEY_FILE_NAME = "encryptAesKeyWithRsaPublicKey";
    private static final String NAME_FILE_TO_ENCRYPT = "ebillet.pdf";
    /**
     * Application entry point
     * @param args file name to encrypt, must be present in resource folder.
     */
    public static void main(String[] args) throws Exception{

        App app = new App();
        File fileToEncrypt = RessourcesFileHelper.getFileFromResources(NAME_FILE_TO_ENCRYPT);

        AesKey aesKey = new AesKey();
        EncryptFile encryptFile = new EncryptFile(fileToEncrypt, aesKey);

         // init encrypt file

      // Generate Rsa Key
  /*      app.generateRsaKey();

        // Encrypt AES Key with RSA private key
        app.encryptAesKeyWithRsaPublicKey(tempAesKey);*/

    }

    /**
     * Encrypt AES Key with RSA public Key
     * @param tempAesKey tempAesKey
     */
    private void encryptAesKeyWithRsaPublicKey(SecretKey tempAesKey) {
        PublicKey rsaPublicKey = this.getRsaPublicKey();
        byte[] encryptAesKeyByte = this.getEncryptAesKeyWithRsaPublicKey(tempAesKey, rsaPublicKey);
        this.writeEncryptedAesKeyByte(encryptAesKeyByte);


    }

    private void writeEncryptedAesKeyByte(byte[] encryptAesKeyByte) {
        try (FileOutputStream encryptedAesKeyOutputStream = new FileOutputStream(ENCRYPTED_AES_KEY_FILE_NAME);) {
            this.writeEncryptedAesKeyByteInFile(encryptAesKeyByte, encryptedAesKeyOutputStream);
        } catch (FileNotFoundException e) {
            LOGGER.error("Error when getting encrypted AES key output stream with file name : "  + ENCRYPTED_AES_KEY_FILE_NAME, e);
        } catch (IOException e) {
            LOGGER.error("Error when writing encrypted AES key output stream with file name : "  + ENCRYPTED_AES_KEY_FILE_NAME, e);

        }

    }

    /**
     *
     * @param encryptAesKeyByte
     * @param encryptedAesKeyOutputStream
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
     * Generate RSA public and private key in file rsa.pub and rsa.key
     */
    private void generateRsaKey() {
        File rsaPrivateKeyFile ;
        File rsaPublicKeyFIle ;
        //generate RSA Private/Public Key only if file doesn't exist
        rsaPrivateKeyFile = new  File(RSA_PRIVATE_KEY_FILE_NAME);
        rsaPublicKeyFIle = new  File(RSA_PUBLIC_KEY_FILE_NAME);

        // If one of private/public key not exist, delete both and generate a new pair
        if (rsaPrivateKeyFile.length() <= 0 || rsaPublicKeyFIle.length() <= 0) {
            LOGGER.debug("File not exist in resources but will be generated.");
            rsaPrivateKeyFile.delete();
            rsaPublicKeyFIle.delete();
            // generate private/public key

            KeyPair kp = generateRsaKeyPair();
            generateRsaPublicKeyFile(kp);
            generateRsaPrivateKeyFile(kp);

        }

    }

    /**
     * Generate rsa private key file.
     * @param kp the KeyPair used to generate rsa public/private key file.
     */
    private void generateRsaPrivateKeyFile(KeyPair kp) {
        PrivateKey rsaPrivateKey = kp.getPrivate();
        generateFileOutputStream(RSA_PRIVATE_KEY_FILE_NAME, rsaPrivateKey.getEncoded());
        LOGGER.info("Private key format: " + rsaPrivateKey.getFormat());
    }

    /**
     *  Generate rsa public key file.
     * @param kp the KeyPair used to generate rsa public/private key file.
     */
    private void generateRsaPublicKeyFile(KeyPair kp) {
        PublicKey rsaPublicKey = kp.getPublic();
        generateFileOutputStream(RSA_PUBLIC_KEY_FILE_NAME, rsaPublicKey.getEncoded());
        LOGGER.info("Public key format: " + rsaPublicKey.getFormat());
    }

    /**
     *
     * @param nameFile
     * @param content
     */
    private void generateFileOutputStream(String nameFile, byte[] content) {
        try (OutputStream out = new FileOutputStream(nameFile);){
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
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance(RSA_ALGORITHM_NAME);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Gennerate rsa key pair, RSA algorithm do not exist : ", e);
        }
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }






    /**
     * Check main argument (size, contenance, ..)
     * @param args argument to check
     */
    private void checkArgument(String[] args) throws Exception{
        String fileName;
        if(args.length == 0) {
            throw new Exception("Error : application has been launch with no args. Please add one arg corresponding to the file name to encrypt.");
        }
        else if(args.length > 1) {
            fileName = args[0];
            LOGGER.warn(String.format("Warning : more than once arg has been added. Only the first one %s will be used.",fileName ));
        }else {
            fileName = args[0];
            LOGGER.debug(String.format("args added : %s ", fileName));
        }
        if (fileName.isEmpty()){
            throw new Exception("Error : application has been launch with bad args. Please add one arg corresponding to the file name to encrypt.");
        }
    }

    /**
     * Get the rsa public key from the file previously generated.
     * @return a rsa PublicKey object
     */
    private PublicKey getRsaPublicKey() {
        File rsaPublicKeyFile = new File(RSA_PUBLIC_KEY_FILE_NAME);
        Path path = Paths.get(rsaPublicKeyFile.toURI());

        byte[] rsaPublicKeyByte = this.getRsaPublicKeyByte(path);

        return this.getRsaPublicKeyFromFileByte(rsaPublicKeyByte);

    }

    /**
     * Get the rsa public key from the byte array (read from te file previously generated)
     * @param rsaPublicKeyByte the byte array from the file.
     * @return a rsa <PublicKey> object
     */
    private PublicKey getRsaPublicKeyFromFileByte(byte[] rsaPublicKeyByte) {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(rsaPublicKeyByte);
        return this.generateRsaPublicKeyFromKeyFactory(keySpec);
    }

    /**
     * Generate rsa public key from key factory.
     * @param keySpec An X509 encoded key spec
     * @return
     */
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
    }

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

    /**
     * Get a key factory with rsa algorithm
     * @return a key factory.
     */
    private  KeyFactory getKeyFactoryFromRsaAlgorithm() {
    KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance(RSA_ALGORITHM_NAME);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Error during getRsaPublicKeyFromFileByte method, " +
                    "no Provider supports a KeyFactorySpi implementation for the specified algorithm : " + RSA_ALGORITHM_NAME, e);
        }
        return kf;
    }
}
