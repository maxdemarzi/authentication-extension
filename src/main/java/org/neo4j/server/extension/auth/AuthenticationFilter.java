/**
 * Copyright (c) 2002-2015 "Neo Technology,"
 * Network Engine for Objects in Lund AB [http://neotechnology.com]
 *
 * This file is part of Neo4j.
 *
 * Neo4j is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package org.neo4j.server.extension.auth;

import org.neo4j.shell.util.json.JSONArray;
import org.neo4j.shell.util.json.JSONException;
import org.neo4j.shell.util.json.JSONObject;
import sun.misc.BASE64Decoder;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;


/**
 * @author tbaum
 * @since 23.01.11
 */
public class AuthenticationFilter implements Filter {
    private final AuthenticationService[] authenticationService;
    private final String realmName;

    private static final ArrayList<String> CYPHER_WRITE_KEYWORDS = new ArrayList<String>() {{
        add("create"); add ("set"); add("merge"); add("delete"); add("remove"); add("drop"); }};

    private static final String CYPHER_ENDPOINT = "/db/data/cypher";
    private static final String BATCH_ENDPOINT = "/db/data/batch";
    private static final String TRANSACTIONAL_ENDPOINT = "/db/data/transaction";

    public AuthenticationFilter(final String realmName, final AuthenticationService... authenticationService) {
        this.authenticationService = authenticationService;
        this.realmName = realmName;
    }

    @Override public void init(final FilterConfig filterConfig) throws ServletException { }

    private byte[] getBody(HttpServletRequest request) throws IOException
    {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        try
        {
            InputStream inputStream = request.getInputStream();

            if (inputStream != null)
            {
                byte[] bytes = new byte[128];
                int bytesRead;
                while ((bytesRead = inputStream.read(bytes)) > 0)
                {
                    buffer.write(bytes, 0, bytesRead);
                }
            }
        }
        catch (IOException e)
        {
            throw e;
        }

        return buffer.toByteArray();
    }

    public void doFilter(final ServletRequest req, final ServletResponse res, final FilterChain chain)
            throws ServletException, IOException {
        if (!(req instanceof HttpServletRequest) || !(res instanceof HttpServletResponse)) {
            throw new ServletException("request not allowed");
        }

        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) res;

        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
        } else {
            final String header = request.getHeader("Authorization");

            if (header != null) {
                byte[] reqBytes = getBody(request);
                HttpServletRequestWrapper wrappedRequest = getWrappedRequest(request, reqBytes);

                final String body = new String(reqBytes, StandardCharsets.UTF_8);
                final String method = hijackMethod(request, body.toLowerCase());

                if (checkAuth(method, header)) {
                    chain.doFilter(wrappedRequest, response);
                } else {
                    sendAuthHeader(request, response);
                }
            } else {
                sendAuthHeader(request, response);
            }
        }
    }

    private String hijackMethod(HttpServletRequest req, String body) {
        String method = req.getMethod();
        String path = req.getRequestURI();

        if ("POST".equalsIgnoreCase(method) && isWriteEndpoint(path) && isNotCypherWrites(path, body)) {
            return "GET";
        }

        return method;
    }

    private ArrayList<String> getQueries(String path, String body) {
        ArrayList<String> queries = new ArrayList<>();

        if (isTransactionalEndPoint(path)) {
            JSONObject jsonObject;
            try {
                jsonObject = new JSONObject(body);
            } catch (JSONException e) {
                e.printStackTrace();
                return null;
            }

            JSONArray jsonArray;
            try {
                jsonArray = jsonObject.getJSONArray("statements");
            } catch (JSONException e) {
                e.printStackTrace();
                return null;
            }

            for (int i = 0, length = jsonArray.length(); i < length; i++) {
                JSONObject query;
                try {
                    query = jsonArray.getJSONObject(i);
                } catch (JSONException e) {
                    e.printStackTrace();
                    return null;
                }

                String statement;
                try {
                    statement = query.getString("statement");
                } catch (JSONException e) {
                    e.printStackTrace();
                    return null;
                }

                queries.add(statement);
            }
        } else {
            if (isBatchEndpoint(path)) {
                JSONArray batch;
                try {
                    batch = new JSONArray(body);
                } catch (JSONException e) {
                    e.printStackTrace();
                    return null;
                }

                for (int i = 0, length = batch.length(); i < length; i ++) {
                    JSONObject job;
                    try {
                        job = batch.getJSONObject(i);
                    } catch (JSONException e) {
                        e.printStackTrace();
                        return null;
                    }
                    String to;
                    try {
                        to = job.getString("to");
                    } catch (JSONException e) {
                        e.printStackTrace();
                        return null;
                    }
                    String method;
                    try {
                        method = job.getString("method");
                    } catch (JSONException e) {
                        e.printStackTrace();
                        return null;
                    }

                    if ("POST".equalsIgnoreCase(method))
                    {
                        if (to.toLowerCase().startsWith("/cypher")) {
                            try {
                                queries.add(job.getJSONObject("body").getString("query"));
                            } catch (JSONException e) {
                                e.printStackTrace();
                                return null;
                            }
                        } else {
                            queries.add("delete"); //force disallowed if query POSTed to any other endpoint
                        }
                    } else {
                        if (!"GET".equalsIgnoreCase(method)) {
                            queries.add("delete"); //force disallowed if request uses any method other than POST or GET
                        }
                    }
                }
            } else {
                if (isCypherEndpoint(path)) {
                    try {
                        queries.add(new JSONObject(body).getString("query"));
                    } catch (JSONException e) {
                        e.printStackTrace();
                        return null;
                    }
                }
            }
        }

        return queries;
    }

    private boolean isNotCypherWrites(String path, String body) {
        ArrayList<String> queries = getQueries(path, body);

        if (queries == null) {
            return false;
        }

        for (String query : queries) {
            String[] tokens = query.split("\\W");
            for (String token : tokens) {
                for (String keyword : CYPHER_WRITE_KEYWORDS) {
                    if (keyword.equalsIgnoreCase(token)) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    private boolean isTransactionalEndPoint(String path) { return path.toLowerCase().startsWith(TRANSACTIONAL_ENDPOINT); }

    private boolean isBatchEndpoint(String path) {
        return path.toLowerCase().startsWith(BATCH_ENDPOINT);
    }

    private boolean isCypherEndpoint(String path) {
        return path.toLowerCase().startsWith(CYPHER_ENDPOINT);
    }

    private boolean isWriteEndpoint(String path) { return isTransactionalEndPoint(path) || isBatchEndpoint(path) || isCypherEndpoint(path); }

    public void destroy() { }

    private boolean checkAuth(String method, String header) throws IOException {
        if (header == null) {
            return false;
        }

        final String encoded = header.substring(header.indexOf(" ") + 1);
        byte[] credentials = new BASE64Decoder().decodeBuffer(encoded);
        for (AuthenticationService service : authenticationService) {
            if (service.hasAccess(method, credentials)) {
                return true;
            }
        }

        return false;
    }

    private void sendAuthHeader(HttpServletRequest request, HttpServletResponse response) throws IOException {
        //request login for anything that is not a REST query
        if (!request.getRequestURI().toLowerCase().startsWith("/db/data")) {
            response.setHeader("WWW-Authenticate", "Basic realm=\"" + realmName + "\"");
        }

        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    private HttpServletRequestWrapper getWrappedRequest(HttpServletRequest httpRequest, final byte[] reqBytes)
            throws IOException {

        final ByteArrayInputStream byteInput = new ByteArrayInputStream(reqBytes);
        return new HttpServletRequestWrapper(httpRequest) {

            @Override
            public ServletInputStream getInputStream() throws IOException {
                return new ServletInputStream() {

                    @Override
                    public int read() throws IOException {
                        return byteInput.read();
                    }
                    @Override
                    public boolean isFinished() {
                        throw new RuntimeException("Not implemented");
                    }

                    @Override
                    public boolean isReady() {
                        throw new RuntimeException("Not implemented");
                    }

                    @Override
                    public void setReadListener(ReadListener readListener) {
                        throw new RuntimeException("Not implemented");
                    }
                };
            }
        };
    }
}