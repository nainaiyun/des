package com.nainaiwang.des.controller;

import com.nainaiwang.des.util.DesedeUtil;
import com.nainaiwang.des.util.RsaUtil;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.tomcat.util.codec.binary.Base64;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
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
        Key pub_key = RsaUtil.getKey(PUBLIC_KEY_FILE);
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
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        byte[] certTrans = new byte[]{};
        if (certs != null && certs.length != 0) {
            certTrans = certs[0].getEncoded();
        }

        String url = "http://128.192.182.51:7001/merchant/KeyTransfer/jh8888";
        //String url = "http://localhost:7001/des/getkey";
        String mch_no = "4100000109";
        String type_no = request.getParameter("type");
        String type = "type=" + type_no;
        HttpClient httpClient = new HttpClient();
        PostMethod method = new PostMethod(url);
        method.addParameter("type", type);
        httpClient.getParams().setSoTimeout(3000);
        int statusCode = httpClient.executeMethod(method);
        if (statusCode != HttpStatus.SC_OK) {
            //错误处理
            LOGGER.error("获取失败，请稍后重试");
            return "获取失败，请稍后重试";
        } else {
            byte[] data = method.getResponseBody();
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
                    RsaUtil.setKey(key, JH_PUBLIC_KEY_FILE);
                } else if ("des".equals(type_no)) {
                    RsaUtil.setKey(key, JH_DES_KEY_FILE);
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

    @RequestMapping(value = "/sendRequest", method = RequestMethod.POST)
    public String sendRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        /**获取请求报文*/
        String requestMessage = request.getParameter("requestMessage");
        if (!requestMessage.equals(new String(requestMessage.getBytes(), "GBK"))) {
            LOGGER.info("字符集不是GBK");
            requestMessage =new String(requestMessage.getBytes(), "GBK");
        }
        /**获取我方私钥*/
        PrivateKey privateKey = (PrivateKey) RsaUtil.getKey(PRIVATE_KEY_FILE);
        /**私钥加密请求报文*/
        byte[] encodedText = RsaUtil.jhEncrypt(requestMessage, JH_PUBLIC_KEY_FILE);
        /**签名*/
        byte[] signature = RsaUtil.sign(privateKey, requestMessage.getBytes());
        /**获取对称秘钥*/
        Key desKey = RsaUtil.getKey(JH_DES_KEY_FILE);
        String dk = new String(Base64.encodeBase64(desKey.getEncoded()));
        /**des加密*/
        byte[] requestMessagePriKeyDes = DesedeUtil.encrypt(Base64.encodeBase64String(encodedText), dk);

        /**建行接口地址*/
        String url = "";
        HttpClient httpClient = new HttpClient();
        PostMethod method = new PostMethod(url);
        method.addParameter("xml", Base64.encodeBase64String(requestMessagePriKeyDes));
        method.addParameter("signature", Base64.encodeBase64String(signature));
        httpClient.getParams().setSoTimeout(3000);
        int statusCode = httpClient.executeMethod(method);
        if (statusCode != HttpStatus.SC_OK) {
            //错误处理
            LOGGER.error("获取失败，请稍后重试");
            return "测试失败";
        } else {
            return "测试成功！";
        }
    }

    @RequestMapping(value = "/receiveRequest", method = RequestMethod.POST)
    public String receiveRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        /**获取请求报文以及数字签名*/
        String requestMessage = request.getParameter("requestMessage");
        String signature = request.getParameter("signature");
        if (!requestMessage.equals(new String(requestMessage.getBytes(), "GBK"))) {
            LOGGER.info("字符集不是GBK");
            requestMessage =new String(requestMessage.getBytes(), "GBK");
        }

        /**获取对称秘钥*/
        Key desKey = RsaUtil.getKey(JH_DES_KEY_FILE);
        String dk = new String(Base64.encodeBase64(desKey.getEncoded()));
        /**des解密*/
        String requestMessagePriKeyDes = DesedeUtil.decrypt(requestMessage.getBytes(), dk);
        /**获取建行公钥*/
        PublicKey publicKey = (PublicKey) RsaUtil.getKey(JH_PUBLIC_KEY_FILE);
        /**验证签名*/
        boolean bool = RsaUtil.verify(publicKey, signature.getBytes(), requestMessagePriKeyDes.getBytes());
        if (bool) {
            /**私钥解密请求报文*/
            String encodedText = RsaUtil.decrypt(requestMessagePriKeyDes, PRIVATE_KEY_FILE);
            /**我方接口地址*/
            String url = "";
            HttpClient httpClient = new HttpClient();
            PostMethod method = new PostMethod(url);
            method.addParameter("xml", encodedText);
            httpClient.getParams().setSoTimeout(3000);
            int statusCode = httpClient.executeMethod(method);
            if (statusCode != HttpStatus.SC_OK) {
                //错误处理
                LOGGER.error("请求失败,请稍后重试,状态码为:" + statusCode);
                return "请求失败,请稍后重试,状态码为:" + statusCode;
            } else {
                return "请求成功！";
            }
        } else {
            LOGGER.error("数字签名错误");
            return "数字签名错误";
        }

    }
}
