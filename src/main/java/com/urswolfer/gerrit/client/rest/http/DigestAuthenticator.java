package com.urswolfer.gerrit.client.rest.http;

import com.google.common.base.CharMatcher;
import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import com.google.common.collect.Iterables;
import com.google.common.collect.Maps;
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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.Proxy;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Formatter;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;

/**
 * Authenticator to process the response to a digest challenge without using Apache.
 * This needs testing!
 * See: https://gist.github.com/slightfoot/5624590
 */
public class DigestAuthenticator implements Authenticator {

    private GerritAuthData authData;
    public static String DIGEST_AUTH_HEADER_NAME = "WWW-Authenticate";
    private String lastNonce = null;
    private long nounceCount = 0;

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
    private String processDigestChallenge(Response response, String auth) {

        //String cnonce = "ab4a7d67a24a1ef1";
        //auth = "Digest realm=\"Gerrit Code Review\", domain=\"http://review.cyanogenmod.org/\", qop=\"auth\", nonce=\"uHv9c6lvHQ8V2f0HgFaB6yKHgWPCAyK/52XfKQ==$\", cnonce=\"" + cnonce + "\"";
        DigestScheme ds = new DigestScheme();
        try {
            ds.processChallenge(new BasicHeader(DIGEST_AUTH_HEADER_NAME, auth));
        } catch (MalformedChallengeException e) {

        }

//        try {
//            Header header = ds.authenticate(new UsernamePasswordCredentials(authData.getLogin(), authData.getPassword()),
//                new BasicHttpRequest(response.request().method(), response.request().url().toString()));
//            return header.getValue();
//        } catch (AuthenticationException e) {
//        }

        String path = response.request().url().toString();
        String username = authData.getLogin();
        String cnonce = createCnonce();
        final HashMap<String, String> authFields = splitAuthFields(auth.substring(7));

        Joiner colonJoiner = Joiner.on(':');

        MessageDigest md5;
        try {
            md5 = MessageDigest.getInstance("MD5");
        }
        catch (NoSuchAlgorithmException e){
            return null;
        }

        String realm = authFields.get("realm");
        String nonce = authFields.get("nonce");
        String qop = authFields.get("qop");
        if (qop == null) qop = "auth";

        if(nonce.equals(this.lastNonce)) {
            ++this.nounceCount;
        } else {
            this.nounceCount = 1L;
            this.lastNonce = nonce;
        }

        StringBuilder sb = new StringBuilder(256);
        Formatter formatter = new Formatter(sb, Locale.US);
        formatter.format("%08x", this.nounceCount);
        formatter.close();
        String nc = sb.toString();

        String HA1;
        try{
            md5.reset();
            String ha1str = colonJoiner.join(username,
                realm, authData.getPassword());
            md5.update(ha1str.getBytes("US-ASCII"));
            byte[] ha1bytes = md5.digest();
            HA1 = bytesToHexString(ha1bytes);
        }
        catch (UnsupportedEncodingException e){
            return null;
        }

        String HA2;
        try{
            md5.reset();
            String ha2str = colonJoiner.join(response.request().method(), path);
            md5.update(ha2str.getBytes("US-ASCII"));
            HA2 = bytesToHexString(md5.digest());
        }
        catch (UnsupportedEncodingException e){
            return null;
        }

        String HA3;
        try{
            md5.reset();
            String ha3str = colonJoiner.join(HA1, nonce, nc, cnonce, qop, HA2);
            md5.update(ha3str.getBytes("US-ASCII"));
            HA3 = bytesToHexString(md5.digest());
        }
        catch (UnsupportedEncodingException e){
            return null;
        }

        sb = new StringBuilder(128);
        sb.append("Digest ");
        sb.append("username" ).append("=\"").append(authData.getLogin()).append("\", ");
        sb.append("realm"    ).append("=\"").append(realm).append("\", ");
        sb.append("nonce"    ).append("=\"").append(nonce).append("\", ");
        sb.append("uri"      ).append("=\"").append(path).append("\" ,");
        sb.append("qop"      ).append('='  ).append("auth").append(", ");
        sb.append("nc"       ).append('='  ).append(nc).append(", ");
        sb.append("cnonce"   ).append("=\"").append(cnonce).append("\", ");
        sb.append("algorithm").append('='  ).append("MD5").append(", ");
        sb.append("response" ).append("=\"").append(HA3).append("\"");

        return sb.toString();
    }

    private static HashMap<String, String> splitAuthFields(String authString)
    {
        final HashMap<String, String> fields = Maps.newHashMap();
        final CharMatcher trimmer = CharMatcher.anyOf("\"\t ");
        final Splitter commas = Splitter.on(',').trimResults().omitEmptyStrings();
        final Splitter equals = Splitter.on('=').trimResults(trimmer).limit(2);
        String[] valuePair;
        for(String keyPair : commas.split(authString)){
            valuePair = Iterables.toArray(equals.split(keyPair), String.class);
            fields.put(valuePair[0], valuePair[1]);
        }
        return fields;
    }

    // TESTED.
    private static final String HEX_LOOKUP = "0123456789abcdef";
    private static String bytesToHexString(byte[] bytes)
    {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (int i = 0; i < bytes.length; i++) {
            sb.append(HEX_LOOKUP.charAt((bytes[i] & 0xF0) >> 4));
            sb.append(HEX_LOOKUP.charAt((bytes[i] & 0x0F) >> 0));
        }
        return sb.toString();
    }

    private static String createCnonce() {
        SecureRandom rnd = new SecureRandom();
        byte[] tmp = new byte[8];
        rnd.nextBytes(tmp);
        return bytesToHexString(tmp);
    }
}
