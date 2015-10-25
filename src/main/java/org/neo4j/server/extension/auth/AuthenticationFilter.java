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

import sun.misc.BASE64Decoder;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.logging.Logger;

/**
 * @author tbaum
 * @since 23.01.11
 */
public class AuthenticationFilter implements Filter {
    private final AuthenticationService[] authenticationService;
    private final String realmName;
    private static final Logger logger = Logger.getLogger(AuthenticationFilter.class.getName());

    private static final ArrayList<String> CYPHER_WRITE_KEYWORDS = new ArrayList<String>() {{
        add("create "); add ("set "); add("merge "); add("delete "); add("remove "); add("drop ");}};

    private static final ArrayList<String> CYPHER_API_ENDPOINTS = new ArrayList<String>() {{
        add("/db/data/transaction"); add("/db/data/cypher"); add("/db/data/batch"); }};


    public AuthenticationFilter(final String realmName, final AuthenticationService... authenticationService) {
        this.authenticationService = authenticationService;
        this.realmName = realmName;
    }

    @Override public void init(final FilterConfig filterConfig) throws ServletException {
    }

    public void doFilter(final ServletRequest req, final ServletResponse res, final FilterChain chain)
            throws ServletException, IOException {
        if (!(req instanceof HttpServletRequest) || !(res instanceof HttpServletResponse)) {
            throw new ServletException("request not allowed");
        }

        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) res;

        ServletInputStream inputStream = request.getInputStream();
        byte[] reqBytes = new byte[Math.max(request.getContentLength(), 0)];

        inputStream.read(reqBytes);
        HttpServletRequestWrapper wrappedRequest = getWrappedRequest(request, reqBytes);
        final String body = new String(reqBytes, StandardCharsets.UTF_8);

        final String header = request.getHeader("Authorization");
        final String method = hijackMethod(request, body.toLowerCase());
        if (header != null) {
            if (checkAuth(method, header)) {
                chain.doFilter(wrappedRequest, response);
            } else {
                sendAuthHeader(response);
            }
        } else {
            sendAuthHeader(response);
        }
    }

    private String hijackMethod(HttpServletRequest req, String body) {
        String method = req.getMethod();
        if("POST".equalsIgnoreCase(method) && isCypherEndpoint(req.getRequestURI()) && isNotCypherWrites(body)) {
            return "GET";
        }

        return method;
    }
    
    private boolean isNotCypherWrites(String body) {
        for (String keyword : CYPHER_WRITE_KEYWORDS) {
            if (body.contains(keyword)) {
                return false;
            }
        }
        return true;
    }

    private boolean isCypherEndpoint(String path) {
        for (String endpoint : CYPHER_API_ENDPOINTS) {
            if (path.toLowerCase().startsWith(endpoint)) {
                return true;
            }
        }
        return false;
    }

    public void destroy() {
    }

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

    private void sendAuthHeader(HttpServletResponse response) throws IOException {
        response.setHeader("WWW-Authenticate", "Basic realm=\"" + realmName + "\"");
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }


    private HttpServletRequestWrapper getWrappedRequest(HttpServletRequest httpRequest, final byte[] reqBytes)
            throws IOException {

        final ByteArrayInputStream byteInput = new ByteArrayInputStream(reqBytes);
        return new HttpServletRequestWrapper(httpRequest) {

            @Override
            public ServletInputStream getInputStream() throws IOException {
                ServletInputStream sis = new ServletInputStream() {

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
                return sis;
            }
        };
    }
}
