package twittertest;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
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

	public enum Method {
		GET,
		POST,
	}

	public static class Keys {

		private String consumerKey;
		private String consumerSecret;
		
		public Keys(String consumerKey, String consumerSecret) {
			this.consumerKey = consumerKey;
			this.consumerSecret = consumerSecret;
		}

		public void setConsumerKey(String consumerKey) {
			this.consumerKey = consumerKey;
		}

		public void setConsumerSecret(String consumerSecret) {
			this.consumerSecret = consumerSecret;
		}

		public String getConsumerKey() {
			return consumerKey;
		}

		public String getConsumerSecret() {
			return consumerSecret;
		}

	}

	public static class Tokens {

		private String accessToken;
		private String accessTokenSecret;

		public Tokens(String accessToken, String accessTokenSecret) {
			this.accessToken = accessToken;
			this.accessTokenSecret = accessTokenSecret;
		}

		public void setAccessToken(String accessToken) {
			this.accessToken = accessToken;
		}

		public void setAccessTokenSecret(String accessTokenSecret) {
			this.accessTokenSecret = accessTokenSecret;
		}

		public String getAccessToken() {
			return accessToken;
		}

		public String getAccessTokenSecret() {
			return accessTokenSecret;
		}

	}

	private static String getUnixTime() {
		return String.valueOf(System.currentTimeMillis() / 1000L);
	}
	
	private static String getStringData(InputStream in) throws IOException {
		StringBuilder sb = new StringBuilder();
		new BufferedReader(new InputStreamReader(in, "UTF-8")).lines().forEach(sb::append);
		return sb.toString();
	}

	private static String urlEncode(String string) throws UnsupportedEncodingException {
		return URLEncoder.encode(string, "UTF-8").replace("+", "%20").replace("*", "%2A").replace("%7E", "~");
	}

	private static String buildParamStr(Map<String, String> params) throws IOException {
		StringBuilder sb = new StringBuilder();
		for (Entry<String, String> param : params.entrySet()) {
			sb.append("&").append(urlEncode(param.getKey())).append("=").append(urlEncode(param.getValue()));
		}
		if(sb.length() > 0)
			return sb.substring(1);
		else
			return sb.toString();
	}
	
	private static String buildAuthHeader(Map<String, String> params) throws IOException {
		StringBuilder sb = new StringBuilder();
		for (Entry<String, String> param : params.entrySet()) {
			sb.append(", ").append(urlEncode(param.getKey())).append("=\"").append(urlEncode(param.getValue())).append("\"");
		} 
		return "OAuth " + sb.substring(2);
	}

	private static String httpGet(String resource, String paramStr, String authHeaderStr) throws IOException {
		HttpURLConnection connection = (HttpURLConnection) new URL(resource + "?" + paramStr).openConnection();
		connection.setRequestMethod("GET");
		connection.setRequestProperty("Authorization", authHeaderStr);
		connection.setRequestProperty("User-Agent", userAgent);
		try {
			return getStringData(connection.getInputStream());
		} catch(IOException e) {
			return getStringData(connection.getErrorStream());
		}
	}

	private static String httpPost(String resource, String paramStr, String authHeaderStr) throws IOException {
		HttpURLConnection connection = (HttpURLConnection) new URL(resource).openConnection();
		connection.setRequestMethod("POST");
		connection.setRequestProperty("Authorization", authHeaderStr);
		connection.setRequestProperty("User-Agent", userAgent);
		connection.setDoOutput(true);
		try(BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(connection.getOutputStream(), "UTF-8"))) {
			bw.write(paramStr);
		}
		try {
			return getStringData(connection.getInputStream());
		} catch(IOException e) {
			return getStringData(connection.getErrorStream());
		}
	}

	private static String userAgent = "TwitterAPITest";

	public static void setUserAgent(String userAgent) {
		TwitterAPI.userAgent = userAgent;
	}

	public static String getAPIResponse(String resource, Method method, SortedMap<String, String> apiParams, Keys keys) throws IOException, GeneralSecurityException {
		SortedMap<String, String> oauthParams = new TreeMap<String, String>() {
			{
				put("oauth_consumer_key", keys.getConsumerKey());
				put("oauth_signature_method", "HMAC-SHA1");
				put("oauth_timestamp", getUnixTime());
				put("oauth_nonce", String.valueOf(Math.random()));
				put("oauth_version", "1.0");
			}
		};
		for(Entry<String, String> param : apiParams.entrySet()) {
			oauthParams.put(param.getKey(), param.getValue());
		}
		String text = method + "&" + urlEncode(resource) + "&" + urlEncode(buildParamStr(oauthParams));
		String key = urlEncode(keys.getConsumerSecret()) + "&";
		SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), "HmacSHA1");
		Mac mac = Mac.getInstance(signingKey.getAlgorithm());
		mac.init(signingKey);
		String signature = Base64.getEncoder().encodeToString(mac.doFinal(text.getBytes()));
		oauthParams.put("oauth_signature", signature);
		for(Entry<String, String> param : apiParams.entrySet()){
			oauthParams.remove(param.getKey());
		}
		switch (method) {
			case GET:
				return httpGet(resource, buildParamStr(apiParams), buildAuthHeader(oauthParams));
			case POST:
				return httpPost(resource, buildParamStr(apiParams), buildAuthHeader(oauthParams));
			default:
				throw new IOException();
		}
	}

	public static String getAPIResponse(String resource, Method method, SortedMap<String, String> apiParams, Keys keys, Tokens tokens) throws IOException, GeneralSecurityException {
		SortedMap<String, String> oauthParams = new TreeMap<String, String>() {
			{
				put("oauth_consumer_key", keys.getConsumerKey());
				put("oauth_signature_method", "HMAC-SHA1");
				put("oauth_timestamp", getUnixTime());
				put("oauth_nonce", String.valueOf(Math.random()));
				put("oauth_version", "1.0");
				put("oauth_token", tokens.getAccessToken());
			}
		};
		for(Entry<String, String> param : apiParams.entrySet()) {
			oauthParams.put(param.getKey(), param.getValue());
		}
		String text = method.name() + "&" + urlEncode(resource) + "&" + urlEncode(buildParamStr(oauthParams));
		String key = urlEncode(keys.getConsumerSecret()) + "&" + urlEncode(tokens.getAccessTokenSecret());
		SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), "HmacSHA1");
		Mac mac = Mac.getInstance(signingKey.getAlgorithm());
		mac.init(signingKey);
		String signature = Base64.getEncoder().encodeToString(mac.doFinal(text.getBytes()));
		oauthParams.put("oauth_signature", signature);
		for(Entry<String, String> param : apiParams.entrySet()) {
			oauthParams.remove(param.getKey());
		}
		switch (method) {
			case GET:
				return httpGet(resource, buildParamStr(apiParams), buildAuthHeader(oauthParams));
			case POST:
				return httpPost(resource, buildParamStr(apiParams), buildAuthHeader(oauthParams));
			default:
				throw new IOException();
		}
	}

}
