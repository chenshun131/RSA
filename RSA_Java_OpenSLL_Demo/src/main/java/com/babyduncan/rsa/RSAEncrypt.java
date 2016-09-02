package com.babyduncan.rsa;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Decoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAEncrypt
{
    /** rsa_public_key.pem文件中的内容 */
    private static final String DEFAULT_PUBLIC_KEY =
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVe+g/3lbn0hKPAoKo66akIjt0" + "\r" +
                    "sh4KCpz7NPF8MpCr8yIc2rijaxxFOVDSvo1eQMWLfgMx9BOkaPMDiu2aDnPKzsYs" + "\r" +
                    "hd/DNY6EeyqIFmmFAGcxHDHSFes+zNe/DI8We+bndVsfgLnyR1kA7AuRWTsEvJvR" + "\r" +
                    "+2fHeGyCpb1mQCTWWQIDAQAB" + "\r";

    /** pkcs8_private_key.pem文件中的内容 */
    private static final String DEFAULT_PRIVATE_KEY =
            "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANV76D/eVufSEo8C" + "\r" +
                    "gqjrpqQiO3SyHgoKnPs08XwykKvzIhzauKNrHEU5UNK+jV5AxYt+AzH0E6Ro8wOK" + "\r" +
                    "7ZoOc8rOxiyF38M1joR7KogWaYUAZzEcMdIV6z7M178MjxZ75ud1Wx+AufJHWQDs" + "\r" +
                    "C5FZOwS8m9H7Z8d4bIKlvWZAJNZZAgMBAAECgYBL1Wf6yBA26PiOtGWVe6AGTeKw" + "\r" +
                    "4VSqXHrHAVeGtq+NZSCI/2j3I+U28dU0B1xQTtHdazXXWMxhaqZoa8FbKCcZDWxl" + "\r" +
                    "T6NAlwCuh4du7XJLR3MRAmqGG4Jr6YPsz1/0doYILiJIMJfMZCqiZNojjolEIbdg" + "\r" +
                    "dD8jW8IHqfzLHz7wAQJBAPYQip7NS89goxD84rbcQBKRZV4tnmxcT5glpFbNJIS+" + "\r" +
                    "UDCOtXNLjj8g9YodI9OyKJ1GAI0ya9H0oDPuhyYZwXkCQQDeGphE7r8/dRPSGKM1" + "\r" +
                    "T8S74ov9Z95wSEyAWpcRG8+Vvty4oZcQEg2C84ea+cWTHggp8PpMQWoiRjr9G4b/" + "\r" +
                    "MGPhAkEAysr/M7mGjTbbrZh9UK9crvDdVizKsAu0HXSIaHFRc4VVmW9D4+2VIjoL" + "\r" +
                    "ovQ5HrNp/ZQ/yB6R9ctibOpcv+3iIQJABnZ5pc/Yqs0KVZu37A41KE5wSmBiXZwM" + "\r" +
                    "9dMtACdyA+Z437p7/dC4qe3SLVVFRYGjNS04600f/H1UrBbH99b9oQJBANdb3cWN" + "\r" +
                    "MIJzQRfRJWjxMbw+B2BiG3jPVFA6GIMwlX39h4pFb6G38ttD9ViWH8FCm9DKoYR2" + "\r" +
                    "/Gijx78gzbUFnIA=" + "\r";

    /** 私钥 */
    private RSAPrivateKey privateKey;

    /** 公钥 */
    private RSAPublicKey publicKey;

    /** 字节数据转字符串专用集合 */
    private static final char[] HEX_CHAR = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};


    /**
     * 获取私钥
     *
     * @return 当前的私钥对象
     */
    public RSAPrivateKey getPrivateKey()
    {
        return privateKey;
    }

    /**
     * 获取公钥
     *
     * @return 当前的公钥对象
     */
    public RSAPublicKey getPublicKey()
    {
        return publicKey;
    }

    /**
     * 随机生成密钥对
     */
    public void genKeyPair()
    {
        KeyPairGenerator keyPairGen = null;
        try
        {
            keyPairGen = KeyPairGenerator.getInstance("RSA");
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
        keyPairGen.initialize(1024, new SecureRandom());
        KeyPair keyPair = keyPairGen.generateKeyPair();
        this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
        this.publicKey = (RSAPublicKey) keyPair.getPublic();
    }

    /**
     * 从文件中输入流中加载 pem公钥文件
     *
     * @param in
     *         公钥输入流
     * @throws Exception
     *         加载公钥时产生的异常
     */
    public void loadPublicKey_PEM(InputStream in) throws Exception
    {
        try
        {
            BufferedReader br = new BufferedReader(new InputStreamReader(in));
            String readLine = null;
            StringBuilder sb = new StringBuilder();
            while ((readLine = br.readLine()) != null)
            {
                if (readLine.charAt(0) == '-')
                {
                    continue;
                }
                else
                {
                    sb.append(readLine);
                    sb.append('\r');
                }
            }
            loadPublicKey(sb.toString());
        }
        catch (IOException e)
        {
            throw new Exception("公钥数据流读取错误");
        }
        catch (NullPointerException e)
        {
            throw new Exception("公钥输入流为空");
        }
    }

    /**
     * 从字符串中加载公钥
     *
     * @param publicKeyStr
     *         公钥数据字符串
     * @throws Exception
     *         加载公钥时产生的异常
     */
    public void loadPublicKey(String publicKeyStr) throws Exception
    {
        try
        {
            BASE64Decoder base64Decoder = new BASE64Decoder();
            byte[] buffer = base64Decoder.decodeBuffer(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            this.publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new Exception("无此算法");
        }
        catch (InvalidKeySpecException e)
        {
            throw new Exception("公钥非法");
        }
        catch (IOException e)
        {
            throw new Exception("公钥数据内容读取错误");
        }
        catch (NullPointerException e)
        {
            throw new Exception("公钥数据为空");
        }
    }

    /**
     * 从文件中输入流中加载 pem私钥文件
     *
     * @param in
     *         私钥文件名
     * @return in
     * @throws Exception
     */
    public void loadPrivateKey_PEM(InputStream in) throws Exception
    {
        try
        {
            BufferedReader br = new BufferedReader(new InputStreamReader(in));
            String readLine = null;
            StringBuilder sb = new StringBuilder();
            while ((readLine = br.readLine()) != null)
            {
                if (readLine.charAt(0) == '-')
                {
                    continue;
                }
                else
                {
                    sb.append(readLine);
                    sb.append('\r');
                }
            }
            loadPrivateKey(sb.toString());
        }
        catch (IOException e)
        {
            throw new Exception("私钥数据读取错误");
        }
        catch (NullPointerException e)
        {
            throw new Exception("私钥输入流为空");
        }
    }

    /**
     * 从字符串中加载私钥
     *
     * @param privateKeyStr
     *         私钥数据字符串
     * @throws Exception
     *         加载私钥时产生的异常
     */
    public void loadPrivateKey(String privateKeyStr) throws Exception
    {
        try
        {
            BASE64Decoder base64Decoder = new BASE64Decoder();
            byte[] buffer = base64Decoder.decodeBuffer(privateKeyStr);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            this.privateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new Exception("无此算法");
        }
        catch (InvalidKeySpecException e)
        {
            throw new Exception("私钥非法");
        }
        catch (IOException e)
        {
            throw new Exception("私钥数据内容读取错误");
        }
        catch (NullPointerException e)
        {
            throw new Exception("私钥数据为空");
        }
    }

    /**
     * 加密过程
     *
     * @param publicKey
     *         公钥
     * @param plainTextData
     *         明文数据
     * @return
     * @throws Exception
     *         加密过程中的异常信息
     */
    public byte[] encrypt(RSAPublicKey publicKey, byte[] plainTextData) throws Exception
    {
        if (publicKey == null)
        {
            throw new Exception("加密公钥为空, 请设置");
        }
        Cipher cipher = null;
        try
        {
            cipher = Cipher.getInstance("RSA", new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] output = cipher.doFinal(plainTextData);
            return output;
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new Exception("无此加密算法");
        }
        catch (NoSuchPaddingException e)
        {
            e.printStackTrace();
            return null;
        }
        catch (InvalidKeyException e)
        {
            throw new Exception("加密公钥非法,请检查");
        }
        catch (IllegalBlockSizeException e)
        {
            throw new Exception("明文长度非法");
        }
        catch (BadPaddingException e)
        {
            throw new Exception("明文数据已损坏");
        }
    }

    /**
     * 解密过程
     *
     * @param privateKey
     *         私钥
     * @param cipherData
     *         密文数据
     * @return 明文
     * @throws Exception
     *         解密过程中的异常信息
     */
    public byte[] decrypt(RSAPrivateKey privateKey, byte[] cipherData) throws Exception
    {
        if (privateKey == null)
        {
            throw new Exception("解密私钥为空, 请设置");
        }
        Cipher cipher = null;
        try
        {
            cipher = Cipher.getInstance("RSA", new BouncyCastleProvider());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] output = cipher.doFinal(cipherData);
            return output;
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new Exception("无此解密算法");
        }
        catch (NoSuchPaddingException e)
        {
            e.printStackTrace();
            return null;
        }
        catch (InvalidKeyException e)
        {
            throw new Exception("解密私钥非法,请检查");
        }
        catch (IllegalBlockSizeException e)
        {
            throw new Exception("密文长度非法");
        }
        catch (BadPaddingException e)
        {
            throw new Exception("密文数据已损坏");
        }
    }

    private PrivateKey privateKey2;
    private PublicKey publicKey2;

    /**
     * 从文件中输入流中加载 der私钥文件
     *
     * @param in
     *         私钥输入流
     * @throws Exception
     *         加载私钥时产生的异常
     */
    public void loadPrivateKey_DER(InputStream in) throws Exception
    {
        try
        {
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
            privateKey2 = keyFactory.generatePrivate(privateKeySpec);
        }
        catch (IOException e)
        {
            throw new Exception("私钥数据流读取错误");
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new Exception("私钥输入流为空");
        }
    }

    /**
     * 解密使用证书加密的字符串,可以是 IOS 加密的字符串
     *
     * @param sec
     */
    public String decodeText(String sec)
    {
        try
        {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
            cipher.init(Cipher.DECRYPT_MODE, privateKey2);
            byte[] base64 = Base64.decodeBase64(sec.getBytes());
            byte[] deBytes = cipher.doFinal(base64);
            return new String(deBytes, "UTF-8");
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
            return "";
        }
        catch (NoSuchPaddingException e)
        {
            e.printStackTrace();
            return "";
        }
        catch (InvalidKeyException e)
        {
            e.printStackTrace();
            return "";
        }
        catch (IllegalBlockSizeException e)
        {
            e.printStackTrace();
            return "";
        }
        catch (BadPaddingException e)
        {
            e.printStackTrace();
            return "";
        }
        catch (UnsupportedEncodingException e)
        {
            e.printStackTrace();
            return "";
        }
    }


    /**
     * 字节数据转十六进制字符串
     *
     * @param data
     *         输入数据
     * @return 十六进制内容
     */
    public static String byteArrayToString(byte[] data)
    {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < data.length; i++)
        {
            //取出字节的高四位 作为索引得到相应的十六进制标识符 注意无符号右移
            stringBuilder.append(HEX_CHAR[(data[i] & 0xf0) >>> 4]);
            //取出字节的低四位 作为索引得到相应的十六进制标识符
            stringBuilder.append(HEX_CHAR[(data[i] & 0x0f)]);
            if (i < data.length - 1)
            {
                stringBuilder.append(' ');
            }
        }
        return stringBuilder.toString();
    }


    public static void main(String[] args)
    {
        RSAEncrypt rsaEncrypt = new RSAEncrypt();
        // 方法一:随机生成密钥对
//         rsaEncrypt.genKeyPair();

        // 方法二:使用写死密钥对
//        // 加载公钥
//        try
//        {
//            rsaEncrypt.loadPublicKey(RSAEncrypt.DEFAULT_PUBLIC_KEY);// 加载文件中的公钥
//            System.out.println("加载公钥成功");
//        }
//        catch (Exception e)
//        {
//            System.err.println(e.getMessage());
//            System.err.println("加载公钥失败");
//        }
//        // 加载私钥
//        try
//        {
//            rsaEncrypt.loadPrivateKey(RSAEncrypt.DEFAULT_PRIVATE_KEY);// 加载文件中的私钥
//            System.out.println("加载私钥成功");
//        }
//        catch (Exception e)
//        {
//            System.err.println(e.getMessage());
//            System.err.println("加载私钥失败");
//        }

        // 方法三:加载pem文件
//        // 加载公钥
//        try
//        {
//            InputStream in = (RSAEncrypt.class.getClassLoader().getResourceAsStream("rsa_public_key.pem"));
//            rsaEncrypt.loadPublicKey_PEM(in);// 加载文件中的公钥
//            in.close();
//            System.out.println("加载公钥成功");
//        }
//        catch (Exception e)
//        {
//            System.err.println(e.getMessage());
//            System.err.println("加载公钥失败");
//        }
//        // 加载私钥
//        try
//        {
//            InputStream in = (RSAEncrypt.class.getClassLoader().getResourceAsStream("pkcs8_private_key.pem"));
//            rsaEncrypt.loadPrivateKey_PEM(in);// 加载文件中的私钥
//            in.close();
//            System.out.println("加载私钥成功");
//        }
//        catch (Exception e)
//        {
//            System.err.println(e.getMessage());
//            System.err.println("加载私钥失败");
//        }
//
//
//        try
//        {
//            // 测试字符串
//            String encryptStr = "陈顺chenshunCHENSHUN123456..<>";
//            // 加密
//            byte[] cipher = rsaEncrypt.encrypt(rsaEncrypt.getPublicKey(), encryptStr.getBytes());
//            // 解密
//            byte[] plainText = rsaEncrypt.decrypt(rsaEncrypt.getPrivateKey(), cipher);
//            System.out.println("密文长度:" + cipher.length);
//            System.out.println(RSAEncrypt.byteArrayToString(cipher));
//            System.out.println("明文长度:" + plainText.length);
//            System.out.println(RSAEncrypt.byteArrayToString(plainText));
//            System.out.println(new String(plainText, "UTF-8"));
//
//            String iosEncryptStr = "P9u44Nb4RKH2w7BA1f7ap8Bp7+jJ2RjM91zpgIf5eMdmTu8J0YSUficn+vuMjlybq9vpSQWpdfOrlwulzt6uS2QXGwiYn45HJeUCeXx0l+7uVX5AS4mxYCIpqiyZe0kztNPwNdv9L43BBGaY4NDcbgRWO2SksGm/HNNmZdL4gNQ=";
//            plainText = rsaEncrypt.decrypt(rsaEncrypt.getPrivateKey(), iosEncryptStr.getBytes());
//            System.out.println("IOS通过证书加密的数据进行解密:" + new String(plainText, "UTF-8"));
//        }
//        catch (Exception e)
//        {
//            System.err.println(e.getMessage());
//        }

        // 方法四:加载der文件
        // 加载私钥
        try
        {
            InputStream in = (RSAEncrypt.class.getClassLoader().getResourceAsStream("pkcs8_private_key.der"));
            rsaEncrypt.loadPrivateKey_DER(in);// 加载文件中的私钥
            in.close();
            System.out.println("加载私钥成功");
        }
        catch (Exception e)
        {
            System.err.println(e.getMessage());
            System.err.println("加载私钥失败");
        }

        try
        {
            String iosEncryptStr = "P9u44Nb4RKH2w7BA1f7ap8Bp7+jJ2RjM91zpgIf5eMdmTu8J0YSUficn+vuMjlybq9vpSQWpdfOrlwulzt6uS2QXGwiYn45HJeUCeXx0l+7uVX5AS4mxYCIpqiyZe0kztNPwNdv9L43BBGaY4NDcbgRWO2SksGm/HNNmZdL4gNQ=";
            System.out.println("IOS通过证书加密的数据进行解密:" + rsaEncrypt.decodeText(iosEncryptStr));
        }
        catch (Exception e)
        {
            System.err.println(e.getMessage());
        }
    }
}