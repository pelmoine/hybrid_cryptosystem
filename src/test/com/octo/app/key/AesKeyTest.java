package com.octo.app.key;

import com.octo.app.file.RessourcesFileHelper;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.SecretKey;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class AesKeyTest {
    private static final String AES_ALGORITHM_NAME = "AES";

    @Test
    public void getSecretKeyTest(){
       AesKey aesKey = new AesKey();
        Assert.assertNotNull(aesKey);
        SecretKey secretKey = aesKey.getSecretKey();
        Assert.assertNotNull(secretKey);
        Assert.assertEquals(AES_ALGORITHM_NAME,secretKey.getAlgorithm());
        Assert.assertFalse(secretKey.isDestroyed());
        //Assert.assertEquals("", secretKey.getFormat());
    }
}
