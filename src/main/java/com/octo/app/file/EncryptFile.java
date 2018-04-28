package com.octo.app.file;

import com.octo.app.key.AesKey;
import org.apache.commons.io.FilenameUtils;
import org.apache.log4j.Logger;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import java.io.*;

public class EncryptFile {
    private static final Logger LOGGER = Logger.getLogger(EncryptFile.class);

    private final File originalFile;
    private final String encryptedFileName;
    private final File encryptFile;

    public EncryptFile(File originalFile, AesKey aesKey){
        checkArgument(originalFile,aesKey);
        this.originalFile = originalFile;
        encryptedFileName = createEncryptedFileName(originalFile.getName());
        encryptFile = encrypt(originalFile, aesKey.getSecretKey(), encryptedFileName);
    }

    private void checkArgument(File originalFile, AesKey aesKey) {
        if(originalFile == null) {
            throw new IllegalArgumentException("Error, impossible to create Encrypt file object with null original file.");
        }
        if(aesKey == null) {
            throw new IllegalArgumentException("Error, impossible to create Encrypt file object with null aes key.");
        }
    }

    private File encrypt(File originalFile, SecretKey secretKey, String encryptedFileName) {
        File encryptFile = null;
        try (InputStream inputStream = new FileInputStream(originalFile)) {
            encryptFile = new File(encryptedFileName);
            encrypt(inputStream, encryptFile, secretKey);
        } catch (final Exception e) {
            LOGGER.error("Exception during encrypt file.", e);
        }
        return encryptFile;
    }
    /**
     *
     * @param fileName
     * @return
     */
    private String createEncryptedFileName(String fileName) {
        final StringBuilder encryptedFileName = new StringBuilder(FilenameUtils.getBaseName(fileName));
        encryptedFileName.append("_encrypted.");
        encryptedFileName.append(FilenameUtils.getExtension(fileName));
        return encryptedFileName.toString();
    }

    /**
     * encrypt an input stream to a File.
     *
     * @param is input stream.
     * @param out output file
     * @param secretKey secret key
     * @throws IOException If the first byte cannot be read for any reason other than the end of the file,
     * if the input stream has been closed, or if some other I/O error occurs.
     * @throws Exception NoSuchAlgorithmException, NoSuchPaddingException or InvalidKeyException due to instanciate cypher.
     */
    public static void encrypt(final InputStream is, final File out, final SecretKey secretKey) throws Exception {
        Cipher aesCipher;
        try {
            aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);
        } catch (final Exception e) {
            throw e;
        }
        try (final FileOutputStream outputStream = new FileOutputStream(out)) {
            copy(is, new CipherOutputStream(outputStream, aesCipher));
        } catch (final IOException e) {
            throw e;
        }
    }

    /**
     * Copy input stream in output stream.
     *
     * @param is input stream
     * @param os output stream
     * @throws IOException If the first byte cannot be read for any reason other than the end of the file,
     * if the input stream has been closed, or if some other I/O error occurs.
     */
    public static void copy(final InputStream is, final OutputStream os) throws IOException{
        int i;
        final byte[] b = new byte[1024];
        try {
            while ((i = is.read(b)) != -1) {
                os.write(b, 0, i);
            }
        } catch (final IOException e) {
            throw e;
        }
    }
}
