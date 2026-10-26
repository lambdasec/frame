package com.example.fetch;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.jsoup.Jsoup;

public class Fetcher {

    private static final String PREVIEW = "https://preview.example.com/render?u=";

    private final OkHttpClient okHttp = new OkHttpClient();

    public String withApache(String target) throws IOException {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpGet get = new HttpGet(PREVIEW + URLEncoder.encode(target, "UTF-8"));
            try (CloseableHttpResponse response = client.execute(get)) {
                return EntityUtils.toString(response.getEntity());
            }
        }
    }

    public String withOkHttp(String target) throws IOException {
        Request request = new Request.Builder().url(PREVIEW + URLEncoder.encode(target, "UTF-8")).build();
        return okHttp.newCall(request).execute().body().string();
    }

    public String withJdkClient(String target) throws IOException {
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(PREVIEW + URLEncoder.encode(target, "UTF-8"))).build();
        try {
            return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString()).body();
        } catch (InterruptedException e) {
            throw new IOException(e);
        }
    }

    public String withUrl(String target) throws IOException {
        try (InputStream in = new URL(PREVIEW + URLEncoder.encode(target, "UTF-8")).openStream()) {
            return new String(in.readAllBytes());
        }
    }

    public String withJsoup(String target) throws IOException {
        return Jsoup.connect(PREVIEW + URLEncoder.encode(target, "UTF-8")).get().text();
    }
}
