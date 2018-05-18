package com.octo.app.file;

import com.octo.app.exception.EncryptFileException;
import org.apache.commons.io.FilenameUtils;
import org.apache.log4j.Logger;

import javax.crypto.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class Encrypter {
    private static final Logger LOGGER = Logger.getLogger(Encrypter.class);
    private final File encryptedFile;
    private Cipher cipher;

    /**
     * Constructor Encrypter for encrypt file.
     *
     * @param originalFile    the original file
     * @param key             the key used to encrypt
     * @param cipherAlgorithm the cipher algorithm
     */
    public Encrypter(File originalFile, SecretKey key, String cipherAlgorithm) {
        checkArguments(originalFile, key, cipherAlgorithm);
        initCipher(key, cipherAlgorithm);
        encryptedFile = createEmptyEncryptedFile(originalFile.getName());
        encrypt(originalFile, encryptedFile);
    }

    /**
     * Constructor Encrypter for encrypt key
     *
     * @param secretKey       the secret key to encrypt
     * @param rsaPrivateKey   the rsa private key used to encrypt
     * @param cipherAlgorithm the cipher algorithm
     */
    public Encrypter(SecretKey secretKey, PublicKey rsaPrivateKey, String cipherAlgorithm) {
        checkArguments(secretKey, rsaPrivateKey, cipherAlgorithm);
        initCipher(rsaPrivateKey, cipherAlgorithm);
        encryptedFile = new File("aes_key_encrypted.key");
        encrypt(secretKey, encryptedFile);
    }

    /**
     * Create the encrypted file name.
     *
     * @param fileName the file name
     * @return the encrypted file name.
     */
    private static String createEncryptedFileName(String fileName) {
        return FilenameUtils.getBaseName(fileName) + "_encrypted." +
                FilenameUtils.getExtension(fileName);
    }

    private void checkArguments(SecretKey secretKey, Key key, String cipherAlgorithm) {
        if (secretKey == null) {
            throw new IllegalArgumentException("Error, impossible to encrypt secret key because it's a null object.");
        }
        checkArguments(key, cipherAlgorithm);
    }

    private void checkArguments(File originalFile, Key key, String cipherAlgorithm) {
        if (originalFile == null) {
            throw new IllegalArgumentException("Error, impossible to encrypt object with null original file.");
        }
        checkArguments(key, cipherAlgorithm);
    }

    private void checkArguments(Key key, String cipherAlgorithm) {
        if (key == null) {
            throw new IllegalArgumentException("Error, impossible to encrypt object with null aes key.");
        }
        if (cipherAlgorithm == null) {
            throw new IllegalArgumentException("Error, impossible to encrypt object with null cipher algorithm.");
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

    /**
     * Encrypte original file and write  it in the encrypt file.
     *
     * @param originalFile original file.
     * @param encryptFile  encrypted file.
     */
    private void encrypt(File originalFile, File encryptFile) {
        byte[] inputBytes = getFileByte(originalFile);
        byte[] outputBytes = getEncryptedBytes(inputBytes);
        writeEncryptedFile(outputBytes, encryptFile);

    }

    /**
     * Write the output byte in the encrypted file.
     *
     * @param outputBytes output bytes.
     * @param encryptFile encrypted file.
     */
    private void writeEncryptedFile(byte[] outputBytes, File encryptFile) {
        try (FileOutputStream outputStream = new FileOutputStream(encryptFile)) {
            outputStream.write(outputBytes);
        } catch (IOException e) {
            throw new EncryptFileException("Error during writting ecrypted file.\n", e);
        }
    }

    /**
     * Get encrypted Bytes
     *
     * @param inputBytes the input byte not encrypted yet.
     * @return the encrypted bytes.
     */
    private byte[] getEncryptedBytes(byte[] inputBytes) {
        try {
            return cipher.doFinal(inputBytes);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptFileException("Error during getting encrypted bytes from the input bytes.\n", e);
        }

    }

    /**
     * Create encrypted file from original file name.
     *
     * @param originalFileName original file name.
     * @return an empty file.
     */
    private File createEmptyEncryptedFile(String originalFileName) {
        String encryptedFileName = createEncryptedFileName(originalFileName);
        return new File(encryptedFileName);
    }

    /**
     * Get byte array from original file.
     *
     * @param originalFile the original file.
     * @return byte array which represent original file.
     */
    private byte[] getFileByte(File originalFile) {
        try (InputStream inputStream = new FileInputStream(originalFile)) {
            byte[] inputBytes = new byte[(int) originalFile.length()];
            int sizeByteRead = inputStream.read(inputBytes);
            checkSizeByteRead(sizeByteRead);

            return inputBytes;
        } catch (IOException e) {
            throw new EncryptFileException("Error during getting file Byte from original file.\n", e);
        }
    }

    /**
     * Check the size byte read.
     *
     * @param sizeByteRead the size byte read.
     */
    private void checkSizeByteRead(int sizeByteRead) {

        switch (sizeByteRead) {
            case 0:
                throw new EncryptFileException("Error during the original file reading : " +
                        "no byte has been reading by the input stream.");
            case -1:
                throw new EncryptFileException("Error during the original file reading : " +
                        "there is no more data because the end of the file has been reached.");
            default:
                LOGGER.info(String.format("There are %s byte read during the getting file byte.", sizeByteRead));
                break;
        }
    }

    /**
     * Initialized the cipher.
     *
     * @param key secret key
     */
    private void initCipher(SecretKey key, String cipherAlgorithm) {
        try {
            cipher = Cipher.getInstance(cipherAlgorithm);
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } catch (final NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException e) {
            throw new EncryptFileException("Error during initialize Cipher object : ", e);
        }
    }

    /**
     * Initialized the cipher.
     *
     * @param key private key  key
     */
    private void initCipher(PublicKey key, String cipherAlgorithm) {
        try {
            cipher = Cipher.getInstance(cipherAlgorithm);
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } catch (final NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException e) {
            throw new EncryptFileException("Error during initialize Cipher object : ", e);
        }
    }

    /**
     * Get encrypted file.
     *
     * @return encrypted file.
     */
    public File getEncryptedFile() {
        return encryptedFile;
    }
}
