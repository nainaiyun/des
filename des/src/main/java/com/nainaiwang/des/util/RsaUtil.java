package com.nainaiwang.des.util;

import org.apache.tomcat.util.codec.binary.Base64;
import sun.misc.BASE64Decoder;

import javax.crypto.Cipher;
import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


public class RsaUtil {
    /**
     * 指定加密算法为RSA
     */
    private static final String ALGORITHM = "RSA";
    /**
     * 密钥长度，用来初始化
     */
    private static final int KEYSIZE = 1024;
    /**
     * 数字签名算法。JDK只提供了MD2withRSA, MD5withRSA, SHA1withRSA，其他的算法需要第三方包才能支持
     */
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    /**
     * 读取秘钥
     *
     * @return
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public static Key getKey(String keyFile) throws IOException, ClassNotFoundException {
        Key publicKey;
        ObjectInputStream ois = null;
        try {
            /** 将文件中的公钥钥对象读出 */
            ois = new ObjectInputStream(new FileInputStream(keyFile));
            publicKey = (Key) ois.readObject();
        } catch (Exception e) {
            throw e;
        } finally {
            ois.close();
        }
        return publicKey;
    }

    /**
     * 写入秘钥
     *
     * @return
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public static Key setKey(String key, String keyFile) throws Exception {
        /** 得到秘钥*/
        Key publicKey = RsaUtil.getToPublicKey(key);
        ObjectOutputStream oos1 = null;
        try {
            /** 用对象流将生成的建行公钥写入文件 */
            oos1 = new ObjectOutputStream(new FileOutputStream(keyFile));
            oos1.writeObject(key);
        } catch (Exception e) {
            throw e;
        } finally {
            /** 清空缓存，关闭文件输出流 */
            oos1.close();
        }
        return publicKey;
    }

    /**
     * 将String转换为PublicKey
     *
     * @param key
     * @return
     * @throws Exception
     */
    public static PublicKey getToPublicKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    /**
     * 将String转换为PrivateKey
     *
     * @param key
     * @return
     * @throws Exception
     */
    public static PrivateKey getToPrivateKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    /**
     * 签名:1. 实例化，传入算法、2. 初始化，传入私钥、3. 签名
     *
     * @param privateKey
     * @param plainText
     * @return
     */
    public static byte[] sign(PrivateKey privateKey, byte[] plainText) {
        try {
            //实例化
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            //初始化，传入私钥
            signature.initSign(privateKey);
            //更新
            signature.update(plainText);
            //签名
            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 验签，三步走: 1. 实例化，传入算法、2. 初始化，传入公钥、3. 验签
     *
     * @param publicKey
     * @param signatureVerify
     * @param plainText
     * @return
     */
    public static boolean verify(PublicKey publicKey, byte[] signatureVerify, byte[] plainText) {
        try {
            //实例化
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            //初始化
            signature.initVerify(publicKey);
            //更新
            signature.update(plainText);
            //验签
            return signature.verify(signatureVerify);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return false;
    }

    /**
     * 公钥加密请求报文
     *
     * @param source
     * @return
     * @throws Exception
     */
    public static byte[] jhEncrypt(String source, String address) throws Exception {
        Key publicKey = getKey(address);
        /** 得到Cipher对象来实现对源数据的RSA加密 */
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] b = source.getBytes();
        /** 执行加密操作 */
        byte[] b1 = cipher.doFinal(b);
        return b1;
    }

    /**
     * 私钥解密请求报文
     *
     * @param cryptograph
     * @return
     * @throws Exception
     */
    public static String decrypt(String cryptograph, String address) throws Exception {
        Key publicKey = getKey(address);
        /** 得到Cipher对象对已用公钥加密的数据进行RSA解密 */
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] b1 = Base64.decodeBase64(cryptograph);
        /** 执行解密操作 */
        byte[] b = cipher.doFinal(b1);
        return new String(b);
    }

    /**
     * 生成密钥对
     * @throws Exception
     */
    private static void generateKeyPair(String publicKeyFile,String privateKeyFile) throws Exception {

        /** RSA算法要求有一个可信任的随机数源 */
        // SecureRandom secureRandom = new SecureRandom();

        /** 为RSA算法创建一个KeyPairGenerator对象 */
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);

        /** 利用上面的随机数据源初始化这个KeyPairGenerator对象 */
        // keyPairGenerator.initialize(KEYSIZE, secureRandom);
        keyPairGenerator.initialize(KEYSIZE);

        /** 生成密匙对 */
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        /** 得到公钥 */
        Key publicKey = keyPair.getPublic();

        System.out.println(keyPair.getPublic());
        /** 得到私钥 */
        Key privateKey = keyPair.getPrivate();

        ObjectOutputStream oos1 = null;
        ObjectOutputStream oos2 = null;
        try {
            /** 用对象流将生成的密钥写入文件 */
            oos1 = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
            oos2 = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
            oos1.writeObject(publicKey);
            oos2.writeObject(privateKey);
        } catch (Exception e) {
            throw e;
        } finally {
            /** 清空缓存，关闭文件输出流 */
            oos1.close();
            oos2.close();
        }
    }

}
