/*
 * Copyright (C) 2015 pengjianbo(pengjianbosoft@gmail.com), Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package cn.finalteam.okhttpfinal;

import android.text.TextUtils;

import java.io.InputStream;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import cn.finalteam.okhttpfinal.https.HttpsCerManager;
import okhttp3.CookieJar;
import okhttp3.Headers;
import okhttp3.OkHttpClient;

/**
 * Desction:
 * Author:pengjianbo
 * Date:15/12/10 上午11:33
 */
public class OkHttpFinal {

    private OkHttpClient okHttpClient;

    private static OkHttpFinal okHttpFinal;
    private OkHttpFinalConfiguration configuration;

    private OkHttpFinal() {
    }




    public synchronized void init(OkHttpFinalConfiguration configuration) {
        this.configuration = configuration;

        X509TrustManager xtm = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                X509Certificate[] x509Certificates = new X509Certificate[0];
                return x509Certificates;
            }
        };

        SSLContext sslContext = null;
        try {
            sslContext = SSLContext.getInstance("SSL");

            sslContext.init(null, new TrustManager[]{xtm}, new SecureRandom());

        } catch (Exception e) {
            e.printStackTrace();
        }
        HostnameVerifier DO_NOT_VERIFY = new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };



        long timeout = configuration.getTimeout();
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                //绕过安全证书
                .sslSocketFactory(sslContext.getSocketFactory())
                //绕过安全证书
                .hostnameVerifier(DO_NOT_VERIFY)

                .connectTimeout(timeout, TimeUnit.MILLISECONDS)
                .writeTimeout(timeout, TimeUnit.MILLISECONDS)
                .readTimeout(timeout, TimeUnit.MILLISECONDS);
        if ( configuration.getHostnameVerifier() != null ) {
            builder.hostnameVerifier(configuration.getHostnameVerifier());
        }

        List<InputStream> certificateList = configuration.getCertificateList();
        if (certificateList != null && certificateList.size() > 0) {
            HttpsCerManager httpsCerManager = new HttpsCerManager(builder);
            httpsCerManager.setCertificates(certificateList);
        }

        CookieJar cookieJar = configuration.getCookieJar();
        if (cookieJar != null) {
            builder.cookieJar(cookieJar);
        }

        if(configuration.getCache() != null) {
            builder.cache(configuration.getCache());
        }

        if (configuration.getAuthenticator() != null){
            builder.authenticator(configuration.getAuthenticator());
        }
        if (configuration.getCertificatePinner() != null) {
            builder.certificatePinner(configuration.getCertificatePinner());
        }
        builder.followRedirects(configuration.isFollowRedirects());
        builder.followSslRedirects(configuration.isFollowSslRedirects());
        if(configuration.getSslSocketFactory() != null) {
            builder.sslSocketFactory(configuration.getSslSocketFactory());
        }
        if(configuration.getDispatcher() != null) {
            builder.dispatcher(configuration.getDispatcher());
        }
        builder.retryOnConnectionFailure(configuration.isRetryOnConnectionFailure());
        if (configuration.getNetworkInterceptorList() != null) {
            builder.networkInterceptors().addAll(configuration.getNetworkInterceptorList());
        }
        if (configuration.getInterceptorList() != null) {
            builder.interceptors().addAll(configuration.getInterceptorList());
        }

        if(configuration.getProxy() != null){
            builder.proxy(configuration.getProxy());
        }
        ILogger.DEBUG = configuration.isDebug();
        ILogger.d("OkHttpFinal init...");
        Constants.DEBUG = configuration.isDebug();

        okHttpClient = builder.build();

    }

    public static OkHttpFinal getInstance() {
        if (okHttpFinal == null) {
            okHttpFinal = new OkHttpFinal();
        }
        return okHttpFinal;
    }

    /**
     * 修改公共请求参数信息
     * @param key
     * @param value
     */
    public void updateCommonParams(String key, String value) {
        boolean add = false;
        List<Part> commonParams = configuration.getCommonParams();
        if (commonParams != null){
            for (Part param:commonParams) {
                if (param != null && TextUtils.equals(param.getKey(), key)){
                    param.setValue(value);
                    add = true;
                    break;
                }
            }
        }
        if (!add) {
            commonParams.add(new Part(key, value));
        }
    }

    /**
     * 修改公共header信息
     * @param key
     * @param value
     */
    public void updateCommonHeader(String key, String value) {
        Headers headers = configuration.getCommonHeaders();
        if ( headers == null){
            headers = new Headers.Builder().build();
        }
        configuration.commonHeaders = headers.newBuilder().set(key, value).build();
    }

    @Deprecated
    public OkHttpClient getOkHttpClient() {
        return okHttpClient;
    }

    public OkHttpClient.Builder getOkHttpClientBuilder() {
        return okHttpClient.newBuilder();
    }

    public List<Part> getCommonParams() {
        return configuration.getCommonParams();
    }

    public List<InputStream> getCertificateList() {
        return configuration.getCertificateList();
    }

    public HostnameVerifier getHostnameVerifier() {
        return configuration.getHostnameVerifier();
    }

    public long getTimeout() {
        return configuration.getTimeout();
    }

    public Headers getCommonHeaders() {
        return configuration.getCommonHeaders();
    }
}
