package com.nainaiwang.des;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.PostMethod;

import java.io.IOException;

public class Des {
    public static void main(String[] args) throws IOException {
        //String url = "http://128.192.182.51:7001/merchant/KeyTransfer/jh8888?type=pub";
        String url = "http://localhost:7001/des/getkey";
        String mch_no = "4100000109";
        HttpClient httpClient = new HttpClient();
        PostMethod method = new PostMethod(url);
        httpClient.getParams().setSoTimeout(3000);
        int statusCode = httpClient.executeMethod(method);
        if (statusCode != HttpStatus.SC_OK) {
            //错误处理
            System.out.println("获取失败，请稍后重试");
        } else {

        }
    }
}
