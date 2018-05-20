package com.octo.app.file.encrypt;

import com.octo.app.exception.EncryptFileException;
import org.apache.commons.io.FilenameUtils;
import org.apache.log4j.Logger;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;

public class FileEncrypter extends AbstractEncrypter {

    private static final Logger LOGGER = Logger.getLogger(FileEncrypter.class);

    /**
     * Main constructor
     *
     * @param originalFile    the original file
     * @param key             the secret key
     * @param cipherAlgorithm the cipher algorithm
     */
    public FileEncrypter(File originalFile, SecretKey key, String cipherAlgorithm) {
        checkArguments(originalFile, key, cipherAlgorithm);
        initCipher(key, cipherAlgorithm);
        setEncryptedFile(createEmptyEncryptedFile(originalFile.getName()));
        encrypt(originalFile, getEncryptedFile());
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

}
