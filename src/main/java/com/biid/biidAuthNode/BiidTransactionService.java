package com.biid.biidAuthNode;

import com.biid.api.service.integrator.api.AuthorizationApi;
import com.biid.api.service.integrator.api.TransactionsApi;
import com.biid.api.service.integrator.gen.ApiClient;
import com.biid.api.service.integrator.gen.ApiException;
import com.biid.api.service.integrator.model.AccessToken;
import com.biid.api.service.integrator.model.CreateTransactionRequest;
import com.biid.api.service.integrator.model.TransactionInfo;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.squareup.okhttp.OkHttpClient;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;
import javax.net.ssl.SSLContext;
import org.apache.commons.io.IOUtils;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.ssl.TrustStrategy;

/**
 * Biid transaction service based on api-biid-integrator library
 *
 * @author Michael Astreiko
 */
public class BiidTransactionService {

    public static final String PUBLIC_API_URL = "https://api.test-biid.com";
    public static final String AUDIENCE = "https://api.test-biid.com";
    public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    public static final String JWE_ALGORITHM = "RSA1_5";
    public static final String JWE_ENCRYPTION_METHOD = "A256GCM";
    public static final String SDK_PUBLIC_KEY_URL = "https://biid-keys.s3.amazonaws.com/sdk/sdk_public_key.der";
    public static final String INTEGRATOR_SITE = "http://demo.biid.com";
    public static final String INTEGRATOR_USERNAME = "jdoe";
    public static final String INTEGRATOR_LANG = "en";

    public void sendAuthTransaction(String username, String entityKey, String entityAppKey, String callbackUrl)
            throws ApiException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException,
                    MalformedURLException, IOException, InvalidKeySpecException, JOSEException {
        CreateTransactionRequest transactionRequest = new CreateTransactionRequest();
        transactionRequest.setExpirationDate(new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
                .format(new Date(new Date().getTime() + 24 * 60 * 60 * 1000)));
        transactionRequest.setType(CreateTransactionRequest.TypeEnum.AUTH);
        transactionRequest.setUsername(username);
        transactionRequest.setCallback(callbackUrl);
        transactionRequest.setActions(Arrays.asList("ACCEPT", "REJECT"));
        transactionRequest.setAssuranceLevel(CreateTransactionRequest.AssuranceLevelEnum.L1);
        TransactionInfo info = new TransactionInfo();
        info.put("title", "Authenticate");
        info.put("description", "Authenticate on site");
        info.put("location", Arrays.asList(2.154007, 41.390205));
        transactionRequest.setInfo(info);
        TransactionsApi transactionsApi = new TransactionsApi(getApiClient(entityAppKey, entityKey));
        transactionsApi.uploadAndSign(transactionRequest);
    }

    private ApiClient getApiClient(String entityAppKey, String eid)
            throws ApiException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException,
                    MalformedURLException, IOException, InvalidKeySpecException, JOSEException {
        String clientToken = generateClientToken(entityAppKey, eid);
        ApiClient apiClient = new ApiClient();
        apiClient.setBasePath(PUBLIC_API_URL);
        
        OkHttpClient httpClient = new OkHttpClient();
        TrustStrategy acceptingTrustStrategy = new TrustStrategy() {
            public boolean isTrusted(X509Certificate[] chain, String authType) {
                return true;
            }
        };
        SSLContext sslContext = SSLContexts.custom().loadTrustMaterial(null, acceptingTrustStrategy).build();
        httpClient.setSslSocketFactory(sslContext.getSocketFactory());
        apiClient.setHttpClient(httpClient);

        AuthorizationApi authorizationApi = new AuthorizationApi(apiClient);
        AccessToken accessToken = authorizationApi.token(GRANT_TYPE, clientToken);
        apiClient.setAccessToken(accessToken.getAccessToken());

        return apiClient;
    }

    private String generateClientToken(String entityAppKey, String eid)
            throws NoSuchAlgorithmException, MalformedURLException, IOException,
                    InvalidKeySpecException, JOSEException {
        Date now = new Date();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder().audience(AUDIENCE).issuer(entityAppKey)
                .issueTime(now).expirationTime(new Date(now.getTime() + 24 * 60 * 60 * 1000))
                .jwtID(UUID.randomUUID().toString()).subject(INTEGRATOR_SITE)
                .claim("hl", INTEGRATOR_LANG).claim("usr", INTEGRATOR_USERNAME);
        if (eid != null) {
            builder.claim("eid", eid);
        }

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.parse(JWE_ALGORITHM), EncryptionMethod.parse(JWE_ENCRYPTION_METHOD))
                .contentType("JWT").build();
        EncryptedJWT jwe = new EncryptedJWT(header, builder.build());
        jwe.encrypt(new RSAEncrypter((RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(IOUtils.toByteArray(new URL(SDK_PUBLIC_KEY_URL))))));
        return jwe.serialize();
    }

}
