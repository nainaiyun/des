//package com.nainaiwang.des;
//
//import java.io.BufferedReader;
//import java.io.IOException;
//import java.io.InputStreamReader;
//import java.io.PrintWriter;
//import java.net.URL;
//import java.net.URLConnection;
//
//import javax.net.ssl.HostnameVerifier;
//import javax.net.ssl.HttpsURLConnection;
//import javax.net.ssl.SSLSession;
//
//import com.nainaiwang.des.util.DesedeUtil;
//
//import com.xwtech.parser.PostRequestHtmlParser;
//import org.apache.logging.log4j.Logger;
//import org.slf4j.LoggerFactory;
//
///**
// * Post请求类——得到HTML响应
// */
//public class PostRequest extends Thread {
//    private String url = "https://b2b.10086.cn/b2b/main/listVendorNoticeResult.html?noticeBean.noticeType=";
//    private String params;
//
//    private static final org.slf4j.Logger LOGGER = LoggerFactory.getLogger(DesedeUtil.class);
//
//    public PostRequest(int noticeType, int perPageSize) {
//
//        this.url = this.url + noticeType;  //拼接URL请求，不包含参数
//        params = "page.currentPage=" + currentPage + "&page.perPageSize=" + perPageSize
//                + "&noticeBean.sourceCH=&noticeBean.source="
//                + "&noticeBean.title=&noticeBean.startDate=&noticeBean.endDate=";
//    }
//
//    public void run() {
//        PrintWriter out = null;
//        BufferedReader in = null;
//        URLConnection conn = null;
//        String result = "";
//        try {
//            conn = new URL(url).openConnection();
//            conn.setUseCaches(false);
//            conn.setRequestProperty("accept", "*/*");
//            conn.setRequestProperty("connection", "Keep-Alive");
//            conn.setRequestProperty("user-agent",
//                    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36");
//            conn.setRequestProperty("X-Requested-With", "XMLHttpRequest");
//            // 发送POST请求必须设置如下两行
//            conn.setDoOutput(true);
//            conn.setDoInput(true);
//
//            // 获取URLConnection对象对应的输出流
//            out = new PrintWriter(conn.getOutputStream());
//            // 发送请求参数
//            out.print(params);
//            // flush输出流的缓冲
//            out.flush();
//            in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
//            String line;
//            while ((line = in.readLine()) != null) {
//                result += line;
//            }
//        } catch (Exception e) {
//            LOGGER.error(currentThread().getName() + "线程Post请求出现问题!\n" + e.getMessage() + "\n");
//        } finally {// 使用finally块来关闭输出流、输入流
//            try {
//                if (out != null) {
//                    out.close();
//                }
//                if (in != null) {
//                    in.close();
//                }
//            } catch (IOException ex) {
//                LOGGER.error(currentThread().getName() + "线程Post请求数据流出现问题!\n" + ex.getMessage() + "\n");
//            }
//        }　
//        //获取到相应结果result ，可以直接在这里进行下一步处理，或者放入到全局字段中，通过其他方式获取......
//    }
//}
