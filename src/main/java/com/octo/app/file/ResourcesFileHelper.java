package com.octo.app.file;

import com.octo.app.exception.EncryptFileException;
import com.octo.app.exception.ResourcesFileException;
import org.apache.commons.io.FilenameUtils;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;

public class ResourcesFileHelper {

    private static final Logger LOGGER = Logger.getLogger(ResourcesFileHelper.class);

    /**
     * Private contructor.
     */
    private ResourcesFileHelper() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * Get file from resources folder.
     * @param nameFile name file to get in resources folder.
     * @return the file.
     */
    public static File getFileFromResources(String nameFile) {
        if(nameFile == null || nameFile.isEmpty()) {
            throw new ResourcesFileException("Error, the name file is null or empty.");
        }
        URL urlFile = ResourcesFileHelper.class.getResource('/' + nameFile);
        if(urlFile == null) {
            throw new ResourcesFileException(String.format("Error, file : %s not exist in resources file.", nameFile));
        }
        try {
            URI uriFile = urlFile.toURI();
            return new File(uriFile);
        } catch (URISyntaxException e) {
            throw new ResourcesFileException(String.format("Error, URL file : %s URL " +
                    "is not formatted strictly according to RFC2396 and cannot be converted " +
                    "to a URI.", urlFile.toString()));
        }

    }

    /**
     * Delete the file.
     *
     * @param file file to delete.
     */
    public static void deleteFile(File file) {
        if (file.length() > 0) {
            try {
                Files.delete(file.toPath());
            } catch (IOException e) {
                throw new ResourcesFileException(String.format("Error during the deleting of %s file.", file.getName()), e);
            }
            LOGGER.info(String.format("%s file has been correctly deleted.", file.getName()));
        }
    }

    /**
     * Get byte array from original file.
     *
     * @param originalFile the original file.
     * @return byte array which represent original file.
     */
    public static byte[] getFileByte(File originalFile) {
        try (InputStream inputStream = new FileInputStream(originalFile)) {
            byte[] inputBytes = new byte[(int) originalFile.length()];
            int sizeByteRead = inputStream.read(inputBytes);
            checkSizeByteRead(sizeByteRead, originalFile.getName());
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
    private static void checkSizeByteRead(int sizeByteRead, String fileName) {

        switch (sizeByteRead) {
            case 0:
                throw new EncryptFileException(String.format("Error during the file %s reading : " +
                        "no byte has been reading by the input stream.", fileName));
            case -1:
                throw new EncryptFileException(String.format("Error during the file %s reading : " +
                        "there is no more data because the end of the file has been reached.", fileName));
            default:
                LOGGER.info(String.format("Reading the %s bytes of file %s ", sizeByteRead, fileName));
                break;
        }
    }

    /**
     * Create the encrypted file name.
     *
     * @param fileName the file name
     * @return the encrypted file name.
     */
    public static String createEncryptedFileName(String fileName) {
        return FilenameUtils.getBaseName(fileName) + "_encrypted." +
                FilenameUtils.getExtension(fileName);
    }

    /**
     * Create the encrypted file name.
     *
     * @param fileName the file name
     * @return the encrypted file name.
     */
    public static String createDecryptedFileName(String fileName) {
        return FilenameUtils.getBaseName(fileName) + "_decrypted." +
                FilenameUtils.getExtension(fileName);
    }
}
