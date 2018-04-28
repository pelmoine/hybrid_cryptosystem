package com.octo.app.file;

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class RessourcesFileHelper {

    /**
     * Private contructor.
     */
    private RessourcesFileHelper() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * Get file from resources folder.
     * @param nameFile name file to get in resources folder.
     * @return the file.
     */
    public static File getFileFromResources(String nameFile) throws URISyntaxException {
        if(nameFile == null || nameFile.isEmpty()) {
            throw new RuntimeException("Error, the name file is null or empty.");
        }
        URL urlFile = RessourcesFileHelper.class.getResource('/' + nameFile);
        if(urlFile == null) {
            throw new RuntimeException(String.format("Error, file : %s not exist in resources file.", nameFile));
        }
        try {
            URI uriFile = urlFile.toURI();
            return new File(uriFile);
        } catch (URISyntaxException e) {
            throw e;
        }

    }
}
