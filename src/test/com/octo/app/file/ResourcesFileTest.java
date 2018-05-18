package com.octo.app.file;

import com.octo.app.exception.ResourcesFileException;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class ResourcesFileTest {

    private static final String FILE_NAME = "ebillet.pdf";
    private static final String NOT_EXISTING_FILE_NAME = "badFileName.pdf";

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

    @Test
    public void getFileFromResourcesFileNameTest(){

        File file = ResourcesFileHelper.getFileFromResources(FILE_NAME);
        Assert.assertNotNull(file);
        Assert.assertEquals(FILE_NAME, file.getName());


    }
}
