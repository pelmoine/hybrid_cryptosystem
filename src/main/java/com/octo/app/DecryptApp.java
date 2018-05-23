package com.octo.app;


import com.octo.app.file.ResourcesFileHelper;
import com.octo.app.file.crypt.decrypt.AesDecrypter;
import com.octo.app.file.crypt.decrypt.RsaDecrypter;
import com.octo.app.key.AesKey;
import com.octo.app.key.RsaKey;

import java.io.File;


/**
 * Program used to decrypt id files, previously crypted by hybrid cryptosystem.
 * <p>
 * <p>
 * 1. Decrypt AES key with RSA private key
 * 2. Decrypt file with AES key decrypted.
 *
 * @author epelmoine
 */
class DecryptApp {
    private static final String AES_CYPHER_PADDING = "AES";
    private static final String RSA_CYPHER_PADDING = "RSA/ECB/PKCS1Padding";
    private static final String NAME_FILE_TO_DECRYPT = "ebillet_encrypted.pdf";
    private static final String AES_KEY_NAME_FILE_TO_DECRYPT = "aes_key_encrypted.key";

    private static final String RSA_PRIVATE_KEY_NAME_FILE = "rsa.key";

    /**
     * Application entry point
     *
     * @param args file name to encrypt, must be present in resource folder.
     */
    public static void main(String[] args) {

        File fileToDecrypt = ResourcesFileHelper.getFileFromResources(NAME_FILE_TO_DECRYPT);
        File aesKeyToDecrypt = ResourcesFileHelper.getFileFromResources(NAME_FILE_TO_DECRYPT);
        // Decrypt AES with RSA private key
        RsaKey rsaKey = new RsaKey();
        rsaKey.loadPrivateKeyFromFile(RSA_PRIVATE_KEY_NAME_FILE);
        RsaDecrypter rsaDecrypter = new RsaDecrypter(aesKeyToDecrypt, rsaKey.getRsaPrivateKey(), RSA_CYPHER_PADDING);
        AesKey aesKey = new AesKey(rsaDecrypter.getResultFile());
        // Decrypt file with AES decrypted
        new AesDecrypter(fileToDecrypt, aesKey.getSecretKey(), AES_CYPHER_PADDING);
        rsaKey.encryptAesKey(aesKey);
    }
}
