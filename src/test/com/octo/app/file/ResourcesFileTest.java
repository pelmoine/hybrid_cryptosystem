package com.octo.app.file;

import com.octo.app.exception.ResourcesFileException;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class ResourcesFileTest {

    private static final String FILE_NAME = "ebillet.pdf";
    private static final String NOT_EXISTING_FILE_NAME = "badFileName.pdf";
    private static final Logger LOGGER = Logger.getLogger(ResourcesFileTest.class);

    @Test
    public void getFileFromResourcesNullFileNameTest(){
        assertThatExceptionOfType(ResourcesFileException.class)
                .isThrownBy(() -> ResourcesFileHelper.getFileFromResources(null))
                .withMessageContaining("Error, the name file is null or empty");

    }

    @Test
    public void getFileFromResourcesEmptyFileNameTest(){
        assertThatExceptionOfType(ResourcesFileException.class)
                .isThrownBy(() -> ResourcesFileHelper.getFileFromResources(""))
                .withMessageContaining("Error, the name file is null or empty");

    }

    @Test
    public void getFileFromResourcesNotExistingFileNameTest(){
        assertThatExceptionOfType(ResourcesFileException.class)
                .isThrownBy(() -> ResourcesFileHelper.getFileFromResources(NOT_EXISTING_FILE_NAME))
                .withMessageContaining("not exist in resources file");

    }

    /**
     * Get file from resources by file name test.
     */
    @Test
    public void getFileFromResourcesFileNameTest(){
        File file = ResourcesFileHelper.getFileFromResources(FILE_NAME);
        Assert.assertNotNull(file);
        Assert.assertEquals(FILE_NAME, file.getName());
    }

    /**
     * delete file test.
     */
    @Test
    public void deleteFileTest() {
        File file = createFile();
        long fileLength = file.length();
        Assert.assertTrue(fileLength > 0);
        ResourcesFileHelper.deleteFile(file);
        Assert.assertNotEquals(fileLength, file.length());
        Assert.assertTrue(file.length() == 0);


    }

    /**
     * Create a file
     *
     * @return the file created
     */
    private File createFile() {
        byte data[] = "test".getBytes();
        Path file = Paths.get("the-file-name");
        try {
            Files.write(file, data);
        } catch (IOException e) {
            LOGGER.error("error during writing in the-file-name file.");
        }
        return file.toFile();
    }
}
