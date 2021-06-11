package com.example.demo;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;

import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.ClientCredentialParameters;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

@Configuration("azureConfig")
public class AzureConfig {

	@Value("${AUTHORITY}")
	private  String authority;
	@Value("${CLIENT_ID}")
    private  String clientId;
	@Value("${SCOPE}")
    private  String scope;
	@Value("${KEY_PATH}")
    private  String keyPath;
	@Value("${CERT_PATH}")
    private  String certPath;
	@Value("${MY_KV}")
    private  String mykv;
	
	@Value("${MySecretName}")
    private  String secretName;
	
	
	
	@Bean("authResult")
	public IAuthenticationResult authResult() throws Exception {
				
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Files.readAllBytes(Paths.get(keyPath)));
        PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(spec);

        InputStream certStream = new ByteArrayInputStream(Files.readAllBytes(Paths.get(certPath)));
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(certStream);

        ConfidentialClientApplication app = ConfidentialClientApplication.builder(
        		clientId,
                ClientCredentialFactory.createFromCertificate(key, cert))
                .authority(authority)
                .build();

        // With client credentials flows the scope is ALWAYS of the shape "resource/.default", as the
        // application permissions need to be set statically (in the portal), and then granted by a tenant administrator

        ClientCredentialParameters clientCredentialParam = ClientCredentialParameters.builder(
                Collections.singleton(scope))
                .build();

        CompletableFuture<IAuthenticationResult> future = app.acquireToken(clientCredentialParam);
        
        return future.get();
					
//		IAuthenticationResult result = Util.getAccessTokenByClientCredentialGrant(config);
//		return result;
	}
	
	@Bean
	@DependsOn("authResult")
	public String hubClientSecret(IAuthenticationResult authResult) throws IOException {
//		String hubClientSecret = 
		System.out.println("Certificate result.accessToken() = "+ authResult.accessToken());
		
	      URL url = new URL(mykv + secretName + "?api-version=2016-10-01");
	      
	      HttpURLConnection conn = (HttpURLConnection) url.openConnection();
	
	      conn.setRequestMethod("GET");
	      conn.setRequestProperty("Authorization", "Bearer " + authResult.accessToken());
	      conn.setRequestProperty("Accept","application/json");
	
	      int httpResponseCode = conn.getResponseCode();
	      if(httpResponseCode == HTTPResponse.SC_OK) {
	
	          StringBuilder response;
	          try(BufferedReader in = new BufferedReader(
	                  new InputStreamReader(conn.getInputStream()))){
	
	              String inputLine;
	              response = new StringBuilder();
	              while (( inputLine = in.readLine()) != null) {
	                  response.append(inputLine);
	              }
	          }
	          System.out.println("SECRET Val = " + response.toString());
	          return response.toString();
	      } else {
	          return String.format("Connection returned HTTP code: %s with message: %s",
	                  httpResponseCode, conn.getResponseMessage());
	      }		
		 
	}

	public String getAuthority() {		
		return authority;
	}
	public String getClientId() {
		return clientId;
	}
	public String getScope() {
		return scope;
	}
	public String getKeyPath() {
		return keyPath;
	}
	public String getCertPath() {
		return certPath;
	}
	public String getMykv() {
		return mykv;
	}
//	public String getEhnamespace() {
//		return ehnamespace;
//	}
//	public String getEhname() {
//		return ehname;
//	}
//	public String getEhClientId() {
//		return ehClientId;
//	}	
}
