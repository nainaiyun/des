package com.nainaiwang.des.controller;

import com.nainaiwang.des.util.DESedeCoder;
import com.nainaiwang.des.util.DesedeUtil;
import com.nainaiwang.des.util.RsaUtil;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.tomcat.util.codec.binary.Base64;
import org.mozilla.universalchardet.UniversalDetector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;


@Controller
@RequestMapping(value = "/abutment")
public class DesController {
    /**
     * PUBLIC_KEY_FILE:我方指定公钥存放文件
     * PRIVATE_KEY_FILE:指定私钥存放文件
     * JH_PUBLIC_KEY_FILE:建行公钥存放文件
     * JH_DES_KEY_FILE:建行对称秘钥存放文件
     */
    private static final String PUBLIC_KEY_FILE = "d:\\java\\key\\PublicKey";
    private static final String PRIVATE_KEY_FILE = "d:\\java\\key\\PrivateKey";
    private static final String JH_PUBLIC_KEY_FILE = "d:\\java\\key\\JHPublicKey";
    private static final String JH_DES_KEY_FILE = "d:\\java\\key\\JHDesKey";

//    private static String PUBLIC_KEY_FILE = "/Users/yanhaopeng/IdeaProject/PublicKey";
//    private static String PRIVATE_KEY_FILE = "/Users/yanhaopeng/IdeaProject/PrivateKey";
//    private static String JH_PUBLIC_KEY_FILE = "/Users/yanhaopeng/IdeaProject/JHPrivateKey";
//    private static String JH_DES_KEY_FILE = "/Users/yanhaopeng/IdeaProject/JHDesKey";

    private static final org.slf4j.Logger LOGGER = LoggerFactory.getLogger(DesedeUtil.class);

    @RequestMapping(value = "/getkey")
    public void getKey(HttpServletRequest request, HttpServletResponse response) throws IOException, ClassNotFoundException {
        String type = request.getParameter("type");
        LOGGER.info("秘钥类型：" + type);
        /**获取我方公钥*/
        Key pub_key = (Key) RsaUtil.getKey(PUBLIC_KEY_FILE,"pub");
        String mch_no = "4100000109";
        OutputStream outputStream = response.getOutputStream();
        /**写入成功应答码*/
        outputStream.write("000000".getBytes());
        String sk = new String(Base64.encodeBase64(pub_key.getEncoded()));
        LOGGER.info("我方提供的公钥为：" + sk);
        byte[] msk = DesedeUtil.encrypt(sk, mch_no);
        LOGGER.info("加密后的公钥为：" + Base64.encodeBase64String(msk));
        LOGGER.info("加密后的公钥长度为：" + msk.length);
        outputStream.write(msk);//encrypt()使用约定的密钥来加密pub_key
        outputStream.flush();
        if (outputStream != null) {
            try {
                outputStream.close();
            } catch (IOException e) {
                LOGGER.error(e.getMessage(), e);
            }
        }
    }

    @ResponseBody
    @RequestMapping(value = "/setkey")
    public String setKey(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String url = "http://128.192.182.51:7001/merchant/KeyTransfer/jh8888";
        //String url = "http://localhost:7001/des/getkey";
        String mch_no = "4100000109";
        String type_no = request.getParameter("type");
        HttpClient httpClient = new HttpClient();
        PostMethod method = new PostMethod(url);
        method.addParameter("type", type_no);
        httpClient.getParams().setSoTimeout(3000);
        int statusCode = httpClient.executeMethod(method);
        LOGGER.info("响应码："+statusCode);
        if (statusCode != HttpStatus.SC_OK) {
            //错误处理
            LOGGER.error("获取失败，请稍后重试");
            return "获取失败，请稍后重试";
        } else {
            byte[] data = method.getResponseBody();
            LOGGER.info("data为"+Base64.encodeBase64String(data));
            byte[] tmp = new byte[6];
            System.arraycopy(data, 0, tmp, 0, tmp.length);
            String return_code = new String(tmp);
            LOGGER.info("返回码：" + return_code);
            if ("000000".equals(return_code)) {
                tmp = new byte[data.length - 6];
                System.arraycopy(data, 6, tmp, 0, tmp.length);
                LOGGER.info("请求的加密后的公钥为：" + Base64.encodeBase64String(tmp));
                String key = DesedeUtil.decrypt(tmp, mch_no); //使用约定密钥对传输的密钥进行解密
                LOGGER.info("请求的解密后的公钥为：" + key);
                if ("pub".equals(type_no)) {
                    RsaUtil.setKey(key, JH_PUBLIC_KEY_FILE,type_no);
                } else if ("des".equals(type_no)) {
                    RsaUtil.setKey(key, JH_DES_KEY_FILE,type_no);
                }
                return "获取成功！";
            } else {
                tmp = new byte[data.length - 6];
                System.arraycopy(data, 6, tmp, 0, tmp.length);
                LOGGER.info("返回错误码：" + return_code + "，错误信息:" + new String(tmp));
                return "返回错误码：" + return_code + "，错误信息:" + new String(tmp);
            }
        }
    }

    @ResponseBody
    @RequestMapping(value = "/sendRequest", method = RequestMethod.POST)
    public String sendRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        request.setCharacterEncoding("GBK");
        /**获取请求报文*/
        String requestMessage = request.getParameter("requestMessage");
        LOGGER.info(requestMessage);
        if (!requestMessage.equals(new String(requestMessage.getBytes(), "GBK"))) {
            LOGGER.info("字符集不是GBK");
            requestMessage =new String(requestMessage.getBytes(), "GBK");
        }
        LOGGER.info("请求报文字符集为："+getEncoding(requestMessage));
        LOGGER.info("请求报文为："+requestMessage);
        /**获取我方私钥*/
        PrivateKey privateKey = (PrivateKey) RsaUtil.getKey(PRIVATE_KEY_FILE,"pri");
        /**签名*/
        byte[] signature = RsaUtil.sign(privateKey, requestMessage.getBytes());

        /**建行公钥加密请求报文*/
//        byte[] encodedText = RsaUtil.jhEncrypt(requestMessage, JH_PUBLIC_KEY_FILE);

        /**获取对称秘钥*/
        String desKey = (String) RsaUtil.getKey(JH_DES_KEY_FILE,"des");
//        String desKey = "Xvc3GekQ1wcT6db4UceXV173NxnpEJcH";
        byte [] bytes = Base64.decodeBase64(desKey);
        /**des加密*/
        byte[] requestMessagePriKeyDes = DESedeCoder.encrypt(requestMessage.getBytes("GBK"), bytes);
        LOGGER.info("加密后byte的原字符集是："+guessEncoding(requestMessagePriKeyDes));
        LOGGER.info("报文密文是："+Base64.encodeBase64String(requestMessagePriKeyDes));
        /**建行接口地址*/
        String url = "http://128.192.182.51:7001/merchant/Tran/jh8888";
        HttpClient httpClient = new HttpClient();
        PostMethod method = new PostMethod(url);

        method.addParameter("xml", Base64.encodeBase64String(requestMessagePriKeyDes));
        method.addParameter("signature", Base64.encodeBase64String(signature));
        httpClient.getParams().setSoTimeout(3000);
        int statusCode = httpClient.executeMethod(method);
        if (statusCode != HttpStatus.SC_OK) {
            //错误处理
            LOGGER.error("响应错误，错误码:"+statusCode);
            return "响应错误，错误码:"+statusCode;
        } else {
            byte[] data = method.getResponseBody();
            LOGGER.info("data长度：" + data.length);
            LOGGER.info("data为"+Base64.encodeBase64String(data));
            byte[] tmp = new byte[10];
            System.arraycopy(data, 0, tmp, 0, tmp.length);
            String signNum = new String(tmp);
            LOGGER.info("数字签名位数：" + signNum);
            Integer sign_num = Integer.parseInt(signNum);

            byte [] sign = new byte[sign_num];
            System.arraycopy(data, 10, sign, 0, sign.length);


            int sum =sign_num+10;
            tmp = new byte[data.length - sum];


            System.arraycopy(data, sum, tmp, 0, tmp.length);

            /**des解密*/
            LOGGER.info("对称秘钥是："+desKey);
            byte [] str = DESedeCoder.decrypt(tmp, bytes);
            LOGGER.info("解密后"+new String(str));

            /**获取建行公钥*/
            PublicKey publicKey = (PublicKey) RsaUtil.getKey(JH_PUBLIC_KEY_FILE,"pub");
            /**验证签名*/
            boolean bool2 = RsaUtil.verify(publicKey, sign, str);
            if (bool2){
                return new String(str);
            }else {
                return "签名错误，可能被篡改！";
            }
        }
    }


    @RequestMapping(value = "/receiveRequest", method = RequestMethod.POST)
    public void receiveRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        /**获取请求报文以及数字签名*/
        String requestMessage = request.getParameter("xml");
        String signature = request.getParameter("signature");
        if (!requestMessage.equals(new String(requestMessage.getBytes(), "GBK"))) {
            LOGGER.info("字符集不是GBK");
            requestMessage =new String(requestMessage.getBytes(), "GBK");
        }

        LOGGER.info("收到建行的请求报文："+requestMessage);

        /**对请求报文以及数字签名进行解码*/
        byte [] bytes = Base64.decodeBase64(requestMessage);
        byte [] signature_byte = Base64.decodeBase64(signature);

        /**获取对称秘钥*/
        String desKey = (String) RsaUtil.getKey(JH_DES_KEY_FILE,"des");
        /**解码deskey*/
        byte [] des_key = Base64.decodeBase64(desKey);
        /**des解密*/
        byte[] requestMessagePriKeyDes = DESedeCoder.decrypt(bytes, des_key);
        LOGGER.info("解密成功！收到建行的请求报文明文："+new String(requestMessagePriKeyDes));
        /**获取建行公钥*/
        PublicKey publicKey = (PublicKey) RsaUtil.getKey(JH_PUBLIC_KEY_FILE,"pub");
        /**验证签名*/
        boolean bool = RsaUtil.verify(publicKey, signature_byte, requestMessagePriKeyDes);
        OutputStream outputStream = response.getOutputStream();
        if (bool) {
            /**私钥解密请求报文*/
            //String encodedText = RsaUtil.decrypt(requestMessagePriKeyDes, PRIVATE_KEY_FILE);
            /**我方接口地址*/
            String url = "http://172.16.2.21:80/bankNotice/jianshe";
            HttpClient httpClient = new HttpClient();
            PostMethod method = new PostMethod(url);
            method.addParameter("xml", Base64.encodeBase64String(requestMessagePriKeyDes));
            httpClient.getParams().setSoTimeout(3000);
            int statusCode = httpClient.executeMethod(method);
            if (statusCode != HttpStatus.SC_OK) {
                //错误处理
                LOGGER.error("请求失败,请稍后重试,状态码为:" + statusCode);
                String msg = "请求失败,请稍后重试,状态码为:" + statusCode;
                outputStream.write(msg.getBytes());
            } else {
                byte[] data = method.getResponseBody();
                LOGGER.info("data为:"+Base64.encodeBase64String(data));
                /**获取我方私钥*/
                PrivateKey privateKey = (PrivateKey) RsaUtil.getKey(PRIVATE_KEY_FILE,"pri");
                /**签名*/
                byte[] signature2 = RsaUtil.sign(privateKey, data);
                int signature2Len =signature2.length;
                String signature2_len=String.format("%010d", signature2Len);
                outputStream.write(signature2_len.getBytes());
                outputStream.write(signature2);
                /**des加密*/
                byte[] str = DESedeCoder.encrypt(data, des_key);
                outputStream.write(str);//encrypt()使用约定的密钥来加密pub_key
            }
        } else {
            LOGGER.error("签名错误，可能被篡改！");
            String msg =  "签名错误，可能被篡改！";
            outputStream.write(msg.getBytes());
        }
        outputStream.flush();
    }

    @RequestMapping(value = "/makeKey", method = RequestMethod.POST)
    public void makeKey(HttpServletRequest request, HttpServletResponse response) throws Exception {

    }

    public static String guessEncoding(byte[] bytes) {
        String DEFAULT_ENCODING = "UTF-8";
        UniversalDetector detector =
                new org.mozilla.universalchardet.UniversalDetector(null);
        detector.handleData(bytes, 0, bytes.length);
        detector.dataEnd();
        String encoding = detector.getDetectedCharset();
        detector.reset();
        if (encoding == null) {
            encoding = DEFAULT_ENCODING;
        }
        return encoding;
    }

    public static String getEncoding(String str) {
        String encode = "GB2312";
        try {
            if (str.equals(new String(str.getBytes(encode), encode))) {
                String s = encode;
                return s;
            }
        } catch (Exception exception) {
        }
        encode = "ISO-8859-1";
        try {
            if (str.equals(new String(str.getBytes(encode), encode))) {
                String s1 = encode;
                return s1;
            }
        } catch (Exception exception1) {
        }
        encode = "UTF-8";
        try {
            if (str.equals(new String(str.getBytes(encode), encode))) {
                String s2 = encode;
                return s2;
            }
        } catch (Exception exception2) {
        }
        encode = "GBK";
        try {
            if (str.equals(new String(str.getBytes(encode), encode))) {
                String s3 = encode;
                return s3;
            }
        } catch (Exception exception3) {
        }
        return "";
    }
}
