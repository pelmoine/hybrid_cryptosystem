package com.octo.app;


import com.octo.app.file.ResourcesFileHelper;
import com.octo.app.file.crypt.encrypt.AesEncrypter;
import com.octo.app.file.crypt.encrypt.RsaEncrypter;
import com.octo.app.key.AesKey;
import com.octo.app.key.RsaKey;

import java.io.File;


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
class EncryptApp {
    private static final String AES_CIPHER_PADDING = "AES";
    private static final String RSA_CIPHER_PADDING = "RSA/ECB/PKCS1Padding";
    private static final String NAME_FILE_TO_ENCRYPT = "ebillet.pdf";
    /**
     * Application entry point
     * @param args file name to encrypt, must be present in resource folder.
     */
    public static void main(String[] args) {

        File fileToEncrypt = ResourcesFileHelper.getFileFromResources(NAME_FILE_TO_ENCRYPT);
        // Encrypt file with AES
        AesKey aesKey = new AesKey();
        new AesEncrypter(fileToEncrypt, aesKey.getSecretKey(), AES_CIPHER_PADDING);
        // Encrypt AES with RSA
        RsaKey rsaKey = new RsaKey();
        new RsaEncrypter(aesKey.getSecretKey(), rsaKey.getRsaPublicKey(), RSA_CIPHER_PADDING);
        rsaKey.encryptAesKey(aesKey);
    }
}
