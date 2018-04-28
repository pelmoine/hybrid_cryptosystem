package com.octo.app.file;

import com.octo.app.file.RessourcesFileHelper;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.net.URISyntaxException;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class ResourcesFileTest {

    private static final String FILE_NAME = "ebillet.pdf";
    private static final String NOT_EXISTING_FILE_NAME = "badFileName.pdf";

    @Test
    public void getFileFromResourcesNullFileNameTest(){
        assertThatExceptionOfType(RuntimeException.class)
                .isThrownBy(() -> RessourcesFileHelper.getFileFromResources(null))
                .withMessageContaining("Error, the name file is null or empty");

    }

    @Test
    public void getFileFromResourcesEmptyFileNameTest(){
        assertThatExceptionOfType(RuntimeException.class)
                .isThrownBy(() -> RessourcesFileHelper.getFileFromResources(""))
                .withMessageContaining("Error, the name file is null or empty");

    }

    @Test
    public void getFileFromResourcesNotExistingFileNameTest(){
        assertThatExceptionOfType(RuntimeException.class)
                .isThrownBy(() -> RessourcesFileHelper.getFileFromResources(NOT_EXISTING_FILE_NAME))
                .withMessageContaining("not exist in resources file");

    }

    @Test
    public void getFileFromResourcesFileNameTest(){
        try {
            File file = RessourcesFileHelper.getFileFromResources(FILE_NAME);
            Assert.assertNotNull(file);
            Assert.assertEquals(FILE_NAME, file.getName());
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

    }
}
