package com.octo.app.file;

import com.octo.app.exception.ResourcesFileException;

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class ResourcesFileHelper {

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
}
