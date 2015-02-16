package twittertest;


import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Map;
import java.util.Map.Entry;
import java.util.SortedMap;
import java.util.TreeMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class TwitterAPI {

	private static String userAgent = "TwitterAPITest";
	
	public static void setUserAgent(String userAgent) {
		TwitterAPI.userAgent = userAgent;
	}

	public static String getAPIResponse(String resource, Method method, SortedMap<String, String> api_params, Keys keys)
		throws IOException, GeneralSecurityException{
		
		SortedMap<String, String> oauth_params = new TreeMap<>();
		oauth_params.put("oauth_consumer_key", keys.getConsumerKey());
		oauth_params.put("oauth_signature_method", "HMAC-SHA1");
		oauth_params.put("oauth_timestamp", String.valueOf(getUnixTime()));
		oauth_params.put("oauth_nonce", String.valueOf(Math.random()));
		oauth_params.put("oauth_version", "1.0");
		
		for(Entry<String, String> param : api_params.entrySet()){
			oauth_params.put(param.getKey(), param.getValue());
		}
		String text = method + "&" + urlEncode(resource) + "&" + urlEncode(buildParamStr(oauth_params));
		String key = urlEncode(keys.getConsumerSecret()) + "&";
		SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), "HmacSHA1");
		Mac mac = Mac.getInstance(signingKey.getAlgorithm());
		mac.init(signingKey);
		String signature = new String(Base64.getEncoder().encode(mac.doFinal(text.getBytes())));
		oauth_params.put("oauth_signature", signature);
		for(Entry<String, String> param : api_params.entrySet()){
			oauth_params.remove(param.getKey());
		}
		
		if(method == Method.GET)
			return httpGet(resource, buildParamStr(api_params), buildAuthHeader(oauth_params));
		else if(method == Method.POST)
			return httpPost(resource, buildParamStr(api_params), buildAuthHeader(oauth_params));
		else
			throw new IOException();
	}
	
	public static String getAPIResponse(String resource, Method method, SortedMap<String, String> api_params, Keys keys, Tokens tokens)
			throws IOException, GeneralSecurityException{
			
		SortedMap<String, String> oauth_params = new TreeMap<>();
		oauth_params.put("oauth_consumer_key", keys.getConsumerKey());
		oauth_params.put("oauth_signature_method", "HMAC-SHA1");
		oauth_params.put("oauth_timestamp", String.valueOf(getUnixTime()));
		oauth_params.put("oauth_nonce", String.valueOf(Math.random()));
		oauth_params.put("oauth_version", "1.0");
		oauth_params.put("oauth_token", tokens.getAccessToken());
		
		for(Entry<String, String> param : api_params.entrySet()){
			oauth_params.put(param.getKey(), param.getValue());
		}
		String text = method.name() + "&" + urlEncode(resource) + "&" + urlEncode(buildParamStr(oauth_params));
		String key = urlEncode(keys.getConsumerSecret()) + "&" + urlEncode(tokens.getAccessTokenSecret());
		SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), "HmacSHA1");
		Mac mac = Mac.getInstance(signingKey.getAlgorithm());
		mac.init(signingKey);
		String signature = new String(Base64.getEncoder().encode(mac.doFinal(text.getBytes())));
		oauth_params.put("oauth_signature", signature);
		for(Entry<String, String> param : api_params.entrySet()){
			oauth_params.remove(param.getKey());
		}
        
		if(method == Method.GET)
			return httpGet(resource, buildParamStr(api_params), buildAuthHeader(oauth_params));
		else if(method == Method.POST)
			return httpPost(resource, buildParamStr(api_params), buildAuthHeader(oauth_params));
		else
			throw new IOException();
	}
	
	private static String httpGet(String resource, String paramStr, String authHeaderStr)
			throws IOException{
		HttpURLConnection connection = (HttpURLConnection)new URL(resource + "?" + paramStr).openConnection();
		connection.setRequestMethod("GET");
		connection.setRequestProperty("Authorization", authHeaderStr);
		connection.setRequestProperty("User-Agent", userAgent);
		try {
			return getStringData(connection.getInputStream());
		} catch(IOException e){
			return getStringData(connection.getErrorStream());
		}
	}
	
	private static String httpPost(String resource, String paramStr, String authHeaderStr)
			throws IOException{
		HttpURLConnection connection = (HttpURLConnection)new URL(resource).openConnection();
		connection.setRequestMethod("POST");
		connection.setRequestProperty("Authorization", authHeaderStr);
		connection.setRequestProperty("User-Agent", userAgent);
		connection.setDoOutput(true);
		try(BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(connection.getOutputStream(), "UTF-8"))){
			bw.write(paramStr);
		}
		try {
			return getStringData(connection.getInputStream());
		} catch(IOException e){
			return getStringData(connection.getErrorStream());
		}
	}
	
	private static String buildParamStr(Map<String, String> params)
			throws IOException{
		StringBuilder sb = new StringBuilder();
		for (Entry<String, String> param : params.entrySet()) {
			sb.append("&").append(urlEncode(param.getKey())).append("=").append(urlEncode(param.getValue()));
		}
		if(sb.length() > 0)
			return sb.substring(1);
		else
			return sb.toString();
	}
	
	private static String buildAuthHeader(Map<String, String> params) 
			throws IOException{
		StringBuilder sb = new StringBuilder();
		for (Entry<String, String> param : params.entrySet()) {
			sb.append(", ").append(urlEncode(param.getKey())).append("=\"").append(urlEncode(param.getValue())).append("\"");
		} 
		return "OAuth " + sb.substring(2);
	}
	
	private static int getUnixTime() {
		return (int)(System.currentTimeMillis() / 1000L);
	}
	
	private static String getStringData(InputStream in) 
			throws IOException{
		StringBuilder sb = new StringBuilder();
		BufferedReader br = new BufferedReader(new InputStreamReader(in, "UTF-8"));
		String line = null;
		while((line = br.readLine()) != null){
			sb.append(line).append("\r\n");
		}
		return sb.toString(); 
	}
	
	private static String urlEncode(String string) 
			throws IOException{
		return URLEncoder.encode(string, "UTF-8").replace("+", "%20");
	}
	
	public static enum Method{
		GET,
		POST
	}
	
	public static class Keys {
		
		private String consumerKey;
		private String consumerSecret;
		
		public Keys(String consumerKey, String consumerSecret) {
			this.consumerKey = consumerKey;
			this.consumerSecret = consumerSecret;
		}
		
		public String getConsumerKey() {
			return consumerKey;
		}
		public void setConsumerKey(String consumerKey) {
			this.consumerKey = consumerKey;
		}
		public String getConsumerSecret() {
			return consumerSecret;
		}
		public void setConsumerSecret(String consumerSecret) {
			this.consumerSecret = consumerSecret;
		}
		
	}
	
	public static class Tokens {
		
		private String accessToken;
		private String accessTokenSecret;
		
		public Tokens(String accessToken, String accessTokenSecret){
			this.accessToken = accessToken;
			this.accessTokenSecret = accessTokenSecret;
		}
		
		public String getAccessToken() {
			return accessToken;
		}
		public void setAccessToken(String accessToken) {
			this.accessToken = accessToken;
		}
		public String getAccessTokenSecret() {
			return accessTokenSecret;
		}
		public void setAccessTokenSecret(String accessTokenSecret) {
			this.accessTokenSecret = accessTokenSecret;
		}
	}

}
