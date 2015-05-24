package com.urswolfer.gerrit.client.rest.http;

import com.squareup.okhttp.Authenticator;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;
import com.urswolfer.gerrit.client.rest.GerritAuthData;
import org.apache.commons.codec.binary.Base64;

import java.io.IOException;
import java.net.Proxy;

public class BasicAuthenticator implements Authenticator {

    private GerritAuthData authData;

    public BasicAuthenticator(GerritAuthData authData) {
        this.authData = authData;
    }

    @Override
    public Request authenticate(Proxy proxy, Response response) throws IOException {
        if (responseCount(response) < 2) {
            String authString = authData.getLogin() + ":" + authData.getPassword();
            byte[] authEncBytes = Base64.encodeBase64(authString.getBytes());
            return response.request().newBuilder().header("Authorization", new String(authEncBytes)).build();
        } else {
            return null;
        }
    }

    @Override
    public Request authenticateProxy(Proxy proxy, Response response) throws IOException {
        return null;
    }

    private int responseCount(Response response) {
        int result = 1;
        while ((response = response.priorResponse()) != null) {
            result++;
        }
        return result;
    }
}
