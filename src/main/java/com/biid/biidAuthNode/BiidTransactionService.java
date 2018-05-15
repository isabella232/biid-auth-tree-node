package com.biid.biidAuthNode;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.apache.commons.io.IOUtils;

/**
 * Biid transaction service based on api-biid-integrator library
 *
 * @author Michael Astreiko
 */
public class BiidTransactionService {


    public BiidTransactionService(String biidSiteUrl, String entityKey, String entityAppKey)
            throws NoSuchAlgorithmException, KeyManagementException {
        this.biidSiteUrl = biidSiteUrl;
        this.entityKey = entityKey;
        this.entityAppKey = entityAppKey;
        trustAllSslConnections();
    }

//    public static final String PUBLIC_API_URL = "https://api.integration-biid.com";
    public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    public static final String JWE_ALGORITHM = "RSA1_5";
    public static final String JWE_ENCRYPTION_METHOD = "A256GCM";
    public static final String SDK_PUBLIC_KEY_URL = "https://biid-keys.s3.amazonaws.com/sdk/sdk_public_key.der";
    public static final String INTEGRATOR_SITE = "https://www.forgerock.com";
    public static final String INTEGRATOR_LANG = "en";

    private String biidSiteUrl;
    private String entityKey;
    private String entityAppKey;


    public String sendAuthTransaction(String username)
            throws /*NoSuchAlgorithmException, KeyStoreException, KeyManagementException,
            MalformedURLException, IOException, InvalidKeySpecException, JOSEException,
            ParseException,*/ Exception {
        URL trUrl = new URL(biidSiteUrl + "/integrator/transactions");
        HttpURLConnection connection = null;
        InputStream respStream = null;
        try {
            connection = (HttpURLConnection) trUrl.openConnection();
            connection.setDoOutput(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Authorization", "Bearer " + getIntegratorAccessToken());
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("Content-Type", "application/json; charset=UTF-8");

            JSONObject payload = new JSONObject();
            payload.put("type", "AUTH");
            payload.put("username", username);
            payload.put("expirationDate", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
                    .format(new Date(new Date().getTime() + 24 * 60 * 60 * 1000)));
            payload.put("actions", Arrays.asList("ACCEPT", "REJECT"));
            payload.put("assuranceLevel", "L1");
            JSONObject info = new JSONObject();
            info.put("title", "Authenticate");
            info.put("description", "Authenticate on site");
            info.put("location", Arrays.asList(2.154007d, 41.390205d));
            payload.put("info", info);
            OutputStreamWriter writer = new OutputStreamWriter(connection.getOutputStream(), "UTF-8");
            writer.write(payload.toJSONString());
            writer.close();

            if (connection.getResponseCode() == 201) {
                respStream = connection.getInputStream();
                JSONObject json = (JSONObject) new JSONParser().parse(respStream);
                return (String) json.get("id");
            } else {
                // TODO: handle response errors in a proper way
                throw new Exception("Unable to create AUTH transaction");
            }
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
            if (respStream != null) {
                respStream.close();
            }
        }
    }

    public String getTransactionStatusById(String id)
            throws /*InvalidKeySpecException, NoSuchAlgorithmException, KeyStoreException,
            KeyManagementException, JOSEException, IOException, ParseException,*/ Exception {
        URL trUrl = new URL(biidSiteUrl + "/integrator/transactions/" + id);
        HttpURLConnection connection = null;
        InputStream respStream = null;
        try {
            connection = (HttpURLConnection) trUrl.openConnection();
            connection.setRequestProperty("Authorization", "Bearer " + getIntegratorAccessToken());
            connection.setRequestProperty("Accept", "application/json");
           
            if (connection.getResponseCode() == 200) {
                respStream = connection.getInputStream();
                JSONObject json = (JSONObject) new JSONParser().parse(respStream);
                return (String) json.get("status");
            } else {
                // TODO: handle response errors in a proper way
                throw new Exception("Unable to get transaction status");
            }
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
            if (respStream != null) {
                respStream.close();
            }
        }
    }

    private String getIntegratorAccessToken()
            throws /*NoSuchAlgorithmException, MalformedURLException, IOException,
            InvalidKeySpecException, JOSEException, ParseException,*/ Exception {
        Date now = new Date();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder().audience(biidSiteUrl).issuer(entityAppKey)
                .issueTime(now).expirationTime(new Date(now.getTime() + 24 * 60 * 60 * 1000))
                .jwtID(UUID.randomUUID().toString()).subject(INTEGRATOR_SITE)
                .claim("hl", INTEGRATOR_LANG);
        if (entityKey != null) {
            builder.claim("eid", entityKey);
        }

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.parse(JWE_ALGORITHM),
                EncryptionMethod.parse(JWE_ENCRYPTION_METHOD)).contentType("JWT").build();
        EncryptedJWT jwe = new EncryptedJWT(header, builder.build());
        URL publicKey = new URL(SDK_PUBLIC_KEY_URL);
        InputStream is = publicKey.openStream();
        try {
            jwe.encrypt(new RSAEncrypter((RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(
                    new X509EncodedKeySpec(IOUtils.toByteArray(is)))));
        } finally {
            is.close();
        }
        String clientToken = jwe.serialize();

        URL authUrl = new URL(biidSiteUrl + "/integrator/oauth2/token"
                + "?grant_type=" + URLEncoder.encode(GRANT_TYPE, "UTF-8")
                + "&assertion=" + URLEncoder.encode(clientToken, "UTF-8"));
        HttpURLConnection connection = null;
        InputStream respStream = null;
        try {
            connection = (HttpURLConnection) authUrl.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            if (connection.getResponseCode() == 200) {
                respStream = connection.getInputStream();
                JSONObject json = (JSONObject) new JSONParser().parse(respStream);
                return (String) json.get("access_token");
            } else {
                // TODO: handle response errors in a proper way
                throw new Exception("Unable to get access token");
            }
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
            if (respStream != null) {
                respStream.close();
            }
        }
    }

    private void trustAllSslConnections() throws NoSuchAlgorithmException, KeyManagementException {
        TrustManager trustManager = new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
            }
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        };
        SSLContext sslContext = SSLContext.getInstance("SSL");
        sslContext.init(null, new TrustManager[] {trustManager}, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
    }
}
