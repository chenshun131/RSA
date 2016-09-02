package com.babyduncan.rsa;

/**
 * User: guohaozhao (guohaozhao@sohu-inc.com)
 * Date: 13-9-5 17:48
 */

import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

public class RSAUtil
{
    private static PrivateKey privateKey;

    static
    {
        try
        {
            InputStream in = (RSAUtil.class.getClassLoader().getResourceAsStream("pkcs8_private_key.der"));
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            byte[] temp = new byte[1024];
            int count = 0;
            while ((count = in.read(temp)) != -1)
            {
                bout.write(temp, 0, count);
                temp = new byte[1024];
            }
            in.close();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bout.toByteArray());
            privateKey = keyFactory.generatePrivate(privateKeySpec);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            throw new RuntimeException("RSA encoder Exception");
        }
    }

    /**
     * 解密使用证书加密的字符串,可以是 IOS 加密的字符串
     *
     * @param sec
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws UnsupportedEncodingException
     */
    public static String decodeText(String sec) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchProviderException, UnsupportedEncodingException
    {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] base64 = Base64.decodeBase64(sec.getBytes());
        byte[] deBytes = cipher.doFinal(base64);
        return new String(deBytes, "UTF-8");
    }

    public static void main(String[] args) throws Exception
    {
        // 解密从IOS端产生的加密数据
        System.out.println(RSAUtil.decodeText("P9u44Nb4RKH2w7BA1f7ap8Bp7+jJ2RjM91zpgIf5eMdmTu8J0YSUficn+vuMjlybq9vpSQWpdfOrlwulzt6uS2QXGwiYn45HJeUCeXx0l+7uVX5AS4mxYCIpqiyZe0kztNPwNdv9L43BBGaY4NDcbgRWO2SksGm/HNNmZdL4gNQ="));
    }
}
