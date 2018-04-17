package com.biid.biidAuthNode;

import javax.net.ssl.SSLContext;
import java.util.Date;
import java.util.UUID;

/**
 * Biid transaction service based on api-biid-integrator library
 *
 * @author Michael Astreiko
 */
public class BiidTransactionService {

    public void sendAuthTransaction(String username, String entityKey, String entityAppKey, String callbackUrl) {
        CreateTransactionRequest transactionRequest = new CreateTransactionRequest();
        transactionRequest.expirationDate = new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'");
        transactionRequest.type = "AUTH";
        transactionRequest.username = username;
        transactionRequest.callback = callbackUrl;
        transactionRequest.actions = ["ACCEPT", "REJECT"];
        TransactionInfo info = new TransactionInfo()
        info.put("title", "Authenticate");
        info.put("description", "Authenticate on site");
        transactionRequest.info = info;
        TransactionsApi transactionsApi = new TransactionsApi(getApiClient(entityKey, entityAppKey));
        transactionsApi.uploadAndSign(transactionRequest)
    }

    ApiClient getApiClient(String selectedEntityAppKey, String eid) {
        try {
            String clientToken = generateClientToken(selectedEntityAppKey, eid)
            ApiClient apiClient = new ApiClient()
            apiClient.basePath = getAudience()
            OkHttpClient httpClient = new OkHttpClient()
            def sslContext = SSLContext.getInstance("SSL")

            sslContext.init(null, [Holders.grailsApplication.mainContext.biidTrustManager] as TrustManager[], null)
            def sslSocketFactory = sslContext.getSocketFactory()
            httpClient.setSslSocketFactory(sslSocketFactory)

            apiClient.setHttpClient(httpClient)
            AuthorizationApi authorizationApi = new AuthorizationApi(apiClient)

            def accessToken = authorizationApi.token(grantType, clientToken)
            apiClient.accessToken = accessToken.accessToken
            return apiClient
        } catch (ex) {
            log.error("Could not create access token ${ex.message}")
            return null
        }
    }

    String generateClientToken(String selectedEntityAppKey, String eid) {
        def now = new Date()
        def builder = new JWTClaimsSet.Builder().audience(audience)
                .issuer(selectedEntityAppKey ?: entityAppKey)
                .issueTime(now).expirationTime(now + 1).subject("http://demo.biid.com")
                .jwtID(UUID.randomUUID().toString()).claim("hl", "en")

        if (eid) {
            builder.claim("eid", eid)
        }

        def jws = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), builder.build())
        jws.sign(new MACSigner(Holders.config.com.biid.security.internalJwt.secret))

        def jwe = new JWEObject(new JWEHeader.Builder(
                JWEAlgorithm.parse(Holders.config.com.biid.security.jwe.algorithm),
                EncryptionMethod.parse(Holders.config.com.biid.security.jwe.encryptionMethod))
                .contentType("JWT").build(), new Payload(jws))
        jwe.encrypt(new RSAEncrypter(sdkPublicKey))
        return jwe.serialize()
    }

}
