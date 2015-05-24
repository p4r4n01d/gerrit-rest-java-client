/*
 * Copyright 2013-2015 Urs Wolfer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.urswolfer.gerrit.client.rest.http;

import com.google.common.base.Optional;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;
import com.google.common.collect.Sets;
import com.google.common.io.CharStreams;
import com.google.gerrit.extensions.restapi.RestApiException;
import com.google.gson.*;
import com.squareup.okhttp.Authenticator;
import com.squareup.okhttp.*;
import com.urswolfer.gerrit.client.rest.GerritAuthData;
import com.urswolfer.gerrit.client.rest.Version;
import com.urswolfer.gerrit.client.rest.gson.DateDeserializer;
import com.urswolfer.gerrit.client.rest.gson.DateSerializer;
import org.apache.http.*;
import org.apache.http.auth.*;
import org.apache.http.auth.Credentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HttpContext;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;


/**
 * This class provides basic http access to the rest interface of a gerrit instance.
 *
 * @author Urs Wolfer
 */
public class GerritRestClient {

    private static final Pattern GERRIT_AUTH_PATTERN = Pattern.compile(".*?xGerritAuth=\"(.+?)\"");
    private static final int CONNECTION_TIMEOUT_MS = 30000;
    private static final String PREEMPTIVE_AUTH = "preemptive-auth";
    private static final Gson GSON = initGson();

    private final GerritAuthData authData;
    private final HttpRequestExecutor httpRequestExecutor;
    private final List<HttpClientBuilderExtension> httpClientBuilderExtensions;

    private final CookieManager cookieManager;
    private final CookieStore cookieStore;
    private final LoginCache loginCache;

    public GerritRestClient(GerritAuthData authData,
                            HttpRequestExecutor httpRequestExecutor,
                            HttpClientBuilderExtension... httpClientBuilderExtensions) {
        this.authData = authData;
        this.httpRequestExecutor = httpRequestExecutor;
        this.httpClientBuilderExtensions = Arrays.asList(httpClientBuilderExtensions);

        cookieManager = new CookieManager();
        cookieManager.setCookiePolicy(CookiePolicy.ACCEPT_ALL);
        cookieStore = cookieManager.getCookieStore();
        loginCache = new LoginCache(authData, cookieStore);
    }

    public enum HttpVerb {
        GET, POST, DELETE, HEAD, PUT
    }

    public static final MediaType MEDIA_TYPE_JSON = MediaType.parse("application/json; charset=utf-8");

    public Gson getGson() {
        return GSON;
    }

    public JsonElement getRequest(String path) throws RestApiException {
        return request(path, null, HttpVerb.GET);
    }

    public JsonElement postRequest(String path, String requestBody) throws RestApiException {
        return request(path, requestBody, HttpVerb.POST);
    }

    public JsonElement putRequest(String path) throws RestApiException {
        return putRequest(path, null);
    }

    public JsonElement putRequest(String path, String requestBody) throws RestApiException {
        return request(path, requestBody, HttpVerb.PUT);
    }

    public JsonElement deleteRequest(String path) throws RestApiException {
        return request(path, null, HttpVerb.DELETE);
    }

    public JsonElement request(String path, String requestBody, HttpVerb verb) throws RestApiException {
        try {
            Response response = doRest(path, requestBody, verb);

            if (response.code() == 403 && loginCache.getGerritAuthOptional().isPresent()) {
                // handle expired sessions: try again with a fresh login
                loginCache.invalidate();
                response = doRest(path, requestBody, verb);
            }

            checkStatusCode(response);
            InputStream resp = response.body().byteStream();
            JsonElement ret = parseResponse(resp);
            if (ret.isJsonNull()) {
                throw new RestApiException("Unexpectedly empty response.");
            }
            return ret;
        } catch (IOException e) {
            throw new RestApiException("Request failed.", e);
        }
    }

    public Response doRest(String path, String requestBody, HttpVerb verb) throws IOException, RestApiException {
        OkHttpClient client = new OkHttpClient();

        Optional<String> gerritAuthOptional = updateGerritAuthWhenRequired(client);

        String uri = authData.getHost();
        // only use /a when http login is required (i.e. we haven't got a gerrit-auth cookie)
        // it would work in most cases also with /a, but it breaks with HTTP digest auth ("Forbidden" returned)
        if (authData.isLoginAndPasswordAvailable() && !gerritAuthOptional.isPresent()) {
            uri += "/a";
        }
        uri += path;

        Request.Builder builder = new Request.Builder()
            .url(uri)
            .addHeader("Accept", MEDIA_TYPE_JSON.toString());

        if (verb == HttpVerb.GET) {
            builder = builder.get();
        } else if (verb == HttpVerb.DELETE) {
            builder = builder.delete();
        } else {
            if (requestBody == null) {
                builder.method(verb.toString(), null);
            } else {
                builder.method(verb.toString(), RequestBody.create(MEDIA_TYPE_JSON, requestBody));
            }
        }

        if (gerritAuthOptional.isPresent()) {
            builder.addHeader("X-Gerrit-Auth", gerritAuthOptional.get());
        }

        return httpRequestExecutor.execute(client, builder);
    }

    private Optional<String> updateGerritAuthWhenRequired(OkHttpClient client) throws IOException {
        if (!loginCache.getHostSupportsGerritAuth()) {
            // We do not not need a cookie here since we are sending credentials as HTTP basic / digest header again.
            // In fact cookies could hurt: googlesource.com Gerrit instances block requests which send a magic cookie
            // named "gi" with a 400 HTTP status (as of 01/29/15).
            cookieStore.removeAll();
            return Optional.absent();
        }
        Optional<HttpCookie> gerritAccountCookie = findGerritAccountCookie();
        if (!gerritAccountCookie.isPresent() || gerritAccountCookie.get().hasExpired()) {
            return updateGerritAuth(client);
        }
        return loginCache.getGerritAuthOptional();
    }

    private Optional<String> updateGerritAuth(OkHttpClient client) throws IOException {
        Optional<String> gerritAuthOptional = tryGerritHttpAuth(client)
            .or(tryGerritHttpFormAuth(client));
        loginCache.setGerritAuthOptional(gerritAuthOptional);
        return gerritAuthOptional;
    }

    /**
     * Handles LDAP auth (but not LDAP_HTTP) which uses a HTML form.
     */
    private Optional<String> tryGerritHttpFormAuth(OkHttpClient client) throws IOException {
        if (!authData.isLoginAndPasswordAvailable()) {
            return Optional.absent();
        }
        String loginUrl = authData.getHost() + "/login/";
        RequestBody formBody = new FormEncodingBuilder()
            .add("username", authData.getLogin())
            .add("password", authData.getPassword())
            .build();

        Request.Builder builder = new Request.Builder().url(loginUrl).post(formBody);
        Response loginResponse = httpRequestExecutor.execute(client, builder);
        return extractGerritAuth(loginResponse);
    }

    /**
     * Try to authenticate against Gerrit instances with HTTP auth (not OAuth or something like that).
     * In case of success we get a GerritAccount cookie. In that case no more login credentials need to be sent as
     * long as we use the *same* HTTP client. Even requests against authenticated rest api (/a) will be processed
     * with the GerritAccount cookie.
     *
     * This is a workaround for "double" HTTP authentication (i.e. reverse proxy *and* Gerrit do HTTP authentication
     * for rest api (/a)).
     *
     * Following old notes from README about the issue:
     * If you have correctly set up a HTTP Password in Gerrit, but still have authentication issues, your Gerrit instance
     * might be behind a HTTP Reverse Proxy (like Nginx or Apache) with enabled HTTP Authentication. You can identify that if
     * you have to enter an username and password (browser password request) for opening the Gerrit web interface. Since this
     * plugin uses Gerrit REST API (with authentication enabled), you need to tell your system administrator that he should
     * disable HTTP Authentication for any request to <code>/a</code> path (e.g. https://git.example.com/a). For these requests
     * HTTP Authentication is done by Gerrit (double HTTP Authentication will not work). For more information see
     * [Gerrit documentation].
     * [Gerrit documentation]: https://gerrit-review.googlesource.com/Documentation/rest-api.html#authentication
     */
    private Optional<String> tryGerritHttpAuth(OkHttpClient client) throws IOException {
        String loginUrl = authData.getHost() + "/login/";
        Request.Builder builder = new Request.Builder().url(loginUrl).get();
        Response loginResponse = httpRequestExecutor.execute(client, builder);
        return extractGerritAuth(loginResponse);
    }

    private Optional<String> extractGerritAuth(Response loginResponse) throws IOException {
        if (loginResponse.code() != 401) {
            Optional<HttpCookie> gerritAccountCookie = findGerritAccountCookie();
            if (gerritAccountCookie.isPresent()) {
                // TODO
                /*Matcher matcher = GERRIT_AUTH_PATTERN.matcher(EntityUtils.toString(loginResponse.getEntity(), Consts.UTF_8));
                if (matcher.find()) {
                    return Optional.of(matcher.group(1));
                }*/
            }
        }
        return Optional.absent();
    }

    private Optional<HttpCookie> findGerritAccountCookie() {
        List<HttpCookie> cookies = cookieStore.getCookies();
        return Iterables.tryFind(cookies, new Predicate<HttpCookie>() {
            @Override
            public boolean apply(HttpCookie cookie) {
                return cookie.getName().equals("GerritAccount");
            }
        });
    }

    private OkHttpClient getHttpClient(HttpContext httpContext) {
        HttpClientBuilder client = HttpClients.custom();

        client.useSystemProperties(); // see also: com.intellij.util.net.ssl.CertificateManager

        OkHttpClient c = new OkHttpClient();
        c.setFollowRedirects(true);
        // we need to get redirected result after login (which is done with POST) for extracting xGerritAuth

        c.setCookieHandler(cookieManager);

        c.setConnectTimeout(CONNECTION_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        c.setReadTimeout(CONNECTION_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        c.setWriteTimeout(CONNECTION_TIMEOUT_MS, TimeUnit.MILLISECONDS);

        CredentialsProvider credentialsProvider = getCredentialsProvider();
        client.setDefaultCredentialsProvider(credentialsProvider);

        if (authData.isLoginAndPasswordAvailable()) {
            credentialsProvider.setCredentials(AuthScope.ANY,
                    new UsernamePasswordCredentials(authData.getLogin(), authData.getPassword()));

            BasicScheme basicAuth = new BasicScheme();
            httpContext.setAttribute(PREEMPTIVE_AUTH, basicAuth);
            client.addInterceptorFirst(new PreemptiveAuthHttpRequestInterceptor(authData));
        }

        c.networkInterceptors().add(new UserAgentInterceptor());
        c.setAuthenticator(new MainAuthenticator(authData));

        for (HttpClientBuilderExtension httpClientBuilderExtension : httpClientBuilderExtensions) {
            client = httpClientBuilderExtension.extend(client, authData);
            credentialsProvider = httpClientBuilderExtension.extendCredentialProvider(client, credentialsProvider, authData);
        }

        return c;
    }

    /**
     * With this impl, it only returns the same credentials once. Otherwise it's possible that a loop will occur.
     * When server returns status code 401, the HTTP client provides the same credentials forever.
     * Since we create a new HTTP client for every request, we can handle it this way.
     */
    private BasicCredentialsProvider getCredentialsProvider() {
        return new BasicCredentialsProvider() {
            private Set<AuthScope> authAlreadyTried = Sets.newHashSet();

            @Override
            public Credentials getCredentials(AuthScope authscope) {
                if (authAlreadyTried.contains(authscope)) {
                    return null;
                }
                authAlreadyTried.add(authscope);
                return super.getCredentials(authscope);
            }
        };
    }

    private JsonElement parseResponse(InputStream response) throws IOException {
        Reader reader = new InputStreamReader(response, Consts.UTF_8);
        reader.skip(5);
        try {
            return new JsonParser().parse(reader);
        } catch (JsonSyntaxException jse) {
            throw new IOException(String.format("Couldn't parse response: %n%s", CharStreams.toString(reader)), jse);
        } finally {
            reader.close();
        }
    }

    private void checkStatusCode(Response response) throws HttpStatusException, IOException {
        int code = response.code();
        switch (code) {
            case HttpStatus.SC_OK:
            case HttpStatus.SC_CREATED:
            case HttpStatus.SC_ACCEPTED:
            case HttpStatus.SC_NO_CONTENT:
                return;
            case HttpStatus.SC_BAD_REQUEST:
            case HttpStatus.SC_UNAUTHORIZED:
            case HttpStatus.SC_PAYMENT_REQUIRED:
            case HttpStatus.SC_FORBIDDEN:
            default:
                String body = "<empty>";
                body = CharStreams.toString(response.body().charStream()).trim();
                String message = String.format("Request not successful. Message: %s. Status-Code: %s. Content: %s.",
                        response.message(), response.code(), body);
                throw new HttpStatusException(response.code(), response.message(), message);
        }
    }

    /**
     * With preemptive auth, it will send the basic authentication response even before the server gives an unauthorized
     * response in certain situations, thus reducing the overhead of making the connection again.
     *
     * Based on:
     * https://subversion.jfrog.org/jfrog/build-info/trunk/build-info-client/src/main/java/org/jfrog/build/client/PreemptiveHttpClient.java
     */
    private static class PreemptiveAuthHttpRequestInterceptor implements HttpRequestInterceptor {
        private GerritAuthData authData;

        public PreemptiveAuthHttpRequestInterceptor(GerritAuthData authData) {
            this.authData = authData;
        }

        public void process(final HttpRequest request, final HttpContext context) throws HttpException, IOException {
            AuthState authState = (AuthState) context.getAttribute(HttpClientContext.TARGET_AUTH_STATE);

            // if no auth scheme available yet, try to initialize it preemptively
            if (authState.getAuthScheme() == null) {
                AuthScheme authScheme = (AuthScheme) context.getAttribute(PREEMPTIVE_AUTH);
                UsernamePasswordCredentials creds = new UsernamePasswordCredentials(authData.getLogin(), authData.getPassword());
                authState.update(authScheme, creds);
            }
        }
    }



    // OkHttp Basic authentication
    private static class MainAuthenticator implements Authenticator {

        private GerritAuthData authData;

        public MainAuthenticator(GerritAuthData authData) {
            this.authData = authData;
        }

        @Override
        public Request authenticate(Proxy proxy, Response response) throws IOException {
            List<Challenge> challenges = response.challenges();
            Authenticator authentator = getAuthenticator(challenges);
            if (authentator != null) {
                return authentator.authenticate(proxy, response);
            } else {
                return null;
            }
        }

        @Override
        public Request authenticateProxy(Proxy proxy, Response response) throws IOException {
            List<Challenge> challenges = response.challenges();
            Authenticator authentator = getAuthenticator(challenges);
            if (authentator != null) {
                return authentator.authenticateProxy(proxy, response);
            } else {
                return null;
            }
        }

        private Authenticator getAuthenticator(List<Challenge> challenges) {
            Authenticator authentator = null;
            Iterator iterator = challenges.iterator();
            while (iterator.hasNext() && authentator != null) {
                Challenge challenge = (Challenge) iterator.next();
                if ("Basic".equals(challenge.getScheme())) {
                    authentator = new BasicAuthenticator(authData);
                } else if ("Digest".equals(challenge.getScheme())) {
                    authentator = new DigestAuthenticator(authData);
                }
            }
            return authentator;
        }
    }



    // http://stackoverflow.com/questions/26509107/how-to-specify-a-default-user-agent-for-okhttp-2-x-requests
    private static class UserAgentInterceptor implements Interceptor {

        @Override
        public Response intercept(Chain chain) throws IOException {
            Request originalRequest = chain.request();
            String userAgent = String.format("gerrit-rest-java-client/%s", Version.get());
            userAgent += " using " + originalRequest.header("User-Agent");
            Request requestWithUserAgent = originalRequest.newBuilder()
                .removeHeader("User-Agent")
                .addHeader("User-Agent", userAgent)
                .build();
            return chain.proceed(requestWithUserAgent);
        }
    }

    private static Gson initGson() {
        GsonBuilder builder = new GsonBuilder();
        builder.registerTypeAdapter(Date.class, new DateDeserializer());
        builder.registerTypeAdapter(Date.class, new DateSerializer());
        builder.setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES);
        return builder.create();
    }
}
