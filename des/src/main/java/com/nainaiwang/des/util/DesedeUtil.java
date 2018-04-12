package com.nainaiwang.des.util;

import org.apache.tomcat.util.codec.binary.Base64;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class DesedeUtil {

    /**
     * 密钥算法
     */
    private static final String KEY_ALGORITHM = "DESede";

    /**
     * 加密/解密算法 / 工作模式 / 填充方式
     * Java 6支持PKCS5Padding填充方式
     * Bouncy Castle支持PKCS7Padding填充方式
     */
    private static final String CIPHER_ALGORITHM = "DESede/ECB/PKCS5Padding";


    /**
     * des加密
     * @param source    源字符串
     * @param key   密钥
     * @return  加密后的密文
     * @throws Exception
     */
    public static String encrypt2(String source, String key) throws Exception {
        byte[] sourceBytes = source.getBytes("UTF-8");
        byte[] keyBytes = Base64.decodeBase64(key);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(keyBytes, KEY_ALGORITHM));
        byte[] decrypted = cipher.doFinal(sourceBytes);
        return Base64.encodeBase64String(decrypted);
    }

    /**
     * des解密
     * @param encryptStr    密文
     * @param key   密钥
     * @return  源字符串
     * @throws Exception
     */
    public static String decrypt2(String encryptStr, String key) throws Exception {
        byte[] sourceBytes = Base64.decodeBase64(encryptStr);
        byte[] keyBytes = Base64.decodeBase64(key);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(keyBytes, KEY_ALGORITHM));
        byte[] decoded = cipher.doFinal(sourceBytes);
        return new String(decoded, "UTF-8");
    }


    /**
     * 对密钥进行DES加密。加密成功后的byte[] 直接传输给客户方。
     *
     * @param key_in : Base64编码的密钥明文
     * @param mch_no : 商户编号
     * @return : DES加密后的密钥
     */
    private static final org.slf4j.Logger LOGGER = LoggerFactory.getLogger(DesedeUtil.class);

    public static byte[] encrypt(String key_in, String mch_no) throws UnsupportedEncodingException {
        SimpleDateFormat sdf = new SimpleDateFormat("yyMMdd");
        String key_str = mch_no + sdf.format(new Date());
        SecretKey key = null;
        try {
            key = makeDESKey(asc2bin(key_str));
        } catch (Exception e) {
            LOGGER.error("密钥生成失败", e);
        }
        if (key == null) {
            LOGGER.error("密钥为空");
            return null;
        }
        byte[] key_byte = Base64.decodeBase64(key_in.getBytes("GBK"));

        Cipher cipher;
        byte[] result = null;
        try {
            cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            result = cipher.doFinal(key_byte);
        } catch (Exception e) {
            LOGGER.error("加密失败。", e);
        }

        return result;
    }


    /**
     * 对密钥进行DES解密。解密成功后的就是对方的密钥。
     *
     * @param key_in : DES加密后的密钥
     * @param mch_no : 商户编号
     * @return : Base64编码的密钥明文
     */
    public static String decrypt(byte[] key_in, String mch_no) {
        String key_out = null;
        SimpleDateFormat sdf = new SimpleDateFormat("yyMMdd");
        String key_str = mch_no + sdf.format(new Date());
        SecretKey key = null;
        try {
            key = makeDESKey(asc2bin(key_str));
        } catch (Exception e) {
            LOGGER.error("密钥生成失败", e);
        }
        if (key == null) {
            LOGGER.error("密钥为空");
            return null;
        }

        Cipher cipher;
        byte[] result = null;
        try {
            cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            result = cipher.doFinal(key_in);
        } catch (Exception e) {
            LOGGER.error("解密失败。", e);
        }
        key_out = Base64.encodeBase64String(result);

        return key_out;
    }

    /**
     * 生成DES密钥
     *
     * @param keybyte
     * @return
     * @throws Exception
     */
    private static SecretKey makeDESKey(byte[] keybyte) throws Exception {
        DESKeySpec deskeyspec = new DESKeySpec(keybyte);
        SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DES");
        return keyfactory.generateSecret(deskeyspec);
    }

    /**
     * 将16进制字符串转换成16进制数字数组
     *
     * @param hexString
     * @return
     */
    private static byte[] asc2bin(String hexString) {
        byte[] hexbyte = hexString.getBytes();
        byte[] bitmap = new byte[hexbyte.length / 2];
        for (int i = 0; i < bitmap.length; i++) {
            hexbyte[i * 2] -= hexbyte[i * 2] > '9' ? 7 : 0;
            hexbyte[i * 2 + 1] -= hexbyte[i * 2 + 1] > '9' ? 7 : 0;
            bitmap[i] = (byte) ((hexbyte[i * 2] << 4 & 0xf0) | (hexbyte[i * 2 + 1] & 0x0f));
        }
        return bitmap;
    }

    public static void main(String[] args) throws UnsupportedEncodingException {
        String str1 = "aaaa你";
        str1 =new String(str1.getBytes("GBK"), "GBK");

        System.out.println("公钥原文:" + str1);
        String str2 = "4100000109";

        byte[] key_byte = encrypt(str1, str2);
        System.out.println("加密后长度:" + key_byte.length);
        System.out.println("加密后数据:" + Base64.encodeBase64String(key_byte));
        String str = decrypt(key_byte, str2);
        System.out.println("解密后数据:" + str);
    }
}
