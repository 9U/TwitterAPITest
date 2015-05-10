import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.TreeMap;

import twittertest.TwitterAPI;
import twittertest.TwitterAPI.Keys;
import twittertest.TwitterAPI.Method;
import twittertest.TwitterAPI.Tokens;

public class MainClass {
	
	public static void main(String[] args) throws IOException, GeneralSecurityException {
		Keys keys = new Keys("", "");
		Tokens tokens = new Tokens("", "");

		String resBody = TwitterAPI.getAPIResponse(
			"https://api.twitter.com/1.1/users/show.json",
			Method.GET,
			new TreeMap<String, String>() {
				{
					put("screen_name", "_srsu");
				}
			},
			keys, tokens);

		System.out.println(resBody);
	}
}
