/*
 * Copyright 2013-2014 Urs Wolfer
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

package com.urswolfer.gerrit.client.rest.http.tools;

import com.google.gerrit.extensions.restapi.RestApiException;
import com.squareup.okhttp.Response;
import com.urswolfer.gerrit.client.rest.http.GerritRestClient;
import com.urswolfer.gerrit.client.rest.tools.Tools;

import java.io.IOException;
import java.io.InputStream;

/**
 * @author Urs Wolfer
 */
public class ToolsRestClient implements Tools {

    private final GerritRestClient gerritRestClient;

    public ToolsRestClient(GerritRestClient gerritRestClient) {
        this.gerritRestClient = gerritRestClient;
    }

    @Override
    public InputStream getCommitMessageHook() throws RestApiException {
        try {
            Response response = gerritRestClient.doRest("/tools/hooks/commit-msg", null, GerritRestClient.HttpVerb.GET);
            int statusCode = response.code();
            if (statusCode >= 200 && statusCode < 400) {
                return response.body().byteStream();
            } else {
                throw new RestApiException("HTTP Error: " + response.message());
            }
        } catch (IOException e) {
            throw new RestApiException("Failed to get commit message hook.", e);
        }
    }
}
