package com.urswolfer.gerrit.client.rest.http;

import com.squareup.okhttp.Authenticator;
import com.squareup.okhttp.Challenge;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;
import com.urswolfer.gerrit.client.rest.GerritAuthData;
import org.apache.http.Header;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.MalformedChallengeException;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.impl.auth.DigestScheme;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicHttpRequest;
import org.apache.http.protocol.BasicHttpContext;

import java.io.IOException;
import java.net.Proxy;
import java.util.List;

/**
 * Authenticator to process the response to a digest challenge without using Apache.
 * This needs testing!
 * See: https://gist.github.com/slightfoot/5624590
 */
public class DigestAuthenticator implements Authenticator {

    private GerritAuthData authData;
    public static String DIGEST_AUTH_HEADER_NAME = "WWW-Authenticate";

    public DigestAuthenticator(GerritAuthData authData) {
        this.authData = authData;
    }

    @Override
    public Request authenticate(Proxy proxy, Response response) throws IOException {
        List<Challenge> challenges = response.challenges();
        String auth = response.header("WWW-Authenticate");
        String responseHeader = null;

        for (Challenge challenge : challenges) {
            if ("Digest".equals(challenge.getScheme())) {
                responseHeader = processDigestChallenge(response, auth);
                break;
            }
        }

        if (responseHeader != null) {
            return response.request().newBuilder().header("Authorization", responseHeader).build();
        } else {
            return null;
        }
    }

    // Check: Not sure about this.
    @Override
    public Request authenticateProxy(Proxy proxy, Response response) throws IOException {
        List<Challenge> challenges = response.challenges();
        String auth = response.header("Proxy-Authenticate");
        String responseHeader = null;

        for (Challenge challenge : challenges) {
            if ("Digest".equals(challenge.getScheme())) {
                responseHeader = processDigestChallenge(response, auth);
                break;
            }
        }

        if (responseHeader != null) {
            return response.request().newBuilder().header("Proxy-Authorization", responseHeader).build();
        } else {
            return null;
        }
    }

    // See: createDigest
    // @link: http://www.docjar.com/html/api/org/apache/http/impl/auth/DigestScheme.java.html
    // Using Apache digest authentication here as it is really difficult to implement otherwise
    private String processDigestChallenge(Response response, String auth) {
        DigestScheme ds = new DigestScheme();
        try {
            ds.processChallenge(new BasicHeader(DIGEST_AUTH_HEADER_NAME, auth));
        } catch (MalformedChallengeException e) {
            return null;
        }

        try {
            Header header = ds.authenticate(new UsernamePasswordCredentials(authData.getLogin(), authData.getPassword()),
                new BasicHttpRequest(response.request().method(), response.request().url().toString()),
                new BasicHttpContext());
            return header.getValue();
        } catch (AuthenticationException e) {
            return null;
        }
    }
}
