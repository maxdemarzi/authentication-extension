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

import com.sun.jersey.core.util.Base64;
import com.sun.jersey.core.util.MultivaluedMapImpl;
import org.junit.Rule;
import org.junit.Test;
import org.neo4j.harness.junit.Neo4jRule;
import org.neo4j.helpers.UTF8;
import org.neo4j.test.server.HTTP;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import java.io.IOException;

import static junit.framework.Assert.assertEquals;

/**
 * @author tbaum
 * @since 31.05.11 21:11
 */
public class TestAuthentification {
    @Rule
    public Neo4jRule neo4j = new Neo4jRule()
            .withExtension("/admin", AuthenticationResource.class)
            .withConfig("dbms.security.auth_enabled","false");

    @Test
    public void listNoUsers() throws Exception {

        HTTP.Response response = HTTP.withHeaders(HttpHeaders.AUTHORIZATION, challengeResponse("neo4j", "master"))
                .GET(neo4j.httpURI().resolve("admin/list").toString());
        assertEquals(200, response.status());

        final String content = response.rawContent();
        assertEquals("{}", content);
    }

    @Test
    public void listAddedUsers() throws Exception {
        addUser("test-rw","pass",true);
        addUser("test-ro", "pass", false);
        HTTP.Response response = HTTP.withHeaders(HttpHeaders.AUTHORIZATION, challengeResponse("neo4j", "master"))
                .GET(neo4j.httpURI().resolve("admin/list").toString());

        assertEquals(200, response.status());
        final String content = response.rawContent();
        assertEquals("{\"test-rw\":\"RW\",\"test-ro\":\"RO\"}", content);
    }

    @Test public void expecting401() throws IOException, InterruptedException {
        HTTP.Response response = HTTP.GET(neo4j.httpURI().resolve("/").toString());
        assertEquals(401, response.status());

        response = HTTP.GET(neo4j.httpURI().resolve("/db/data").toString());
        assertEquals(401, response.status());

        response = HTTP.GET(neo4j.httpURI().resolve("/admin/add-user-ro").toString());
        assertEquals(401, response.status());

        response = HTTP.GET(neo4j.httpURI().resolve("/admin/add-user-rw").toString());
        assertEquals(401, response.status());

        response = HTTP.GET(neo4j.httpURI().resolve("/admin/remove-user").toString());
        assertEquals(401, response.status());
    }

    @Test public void addRoAndRemoveUserTest() throws IOException, InterruptedException {

        addUser("test", "pass", false);

        HTTP.Response response = HTTP.withHeaders(HttpHeaders.AUTHORIZATION, challengeResponse("test", "pass"))
                .GET(neo4j.httpURI().resolve("/").toString());
        assertEquals(200, response.status());
        response = HTTP.withHeaders(HttpHeaders.AUTHORIZATION, challengeResponse("test", "pass"))
                .GET(neo4j.httpURI().resolve("/db/data").toString());
        assertEquals(200, response.status());
        response = HTTP.withHeaders(HttpHeaders.AUTHORIZATION, challengeResponse("test", "pass"))
                .POST(neo4j.httpURI().resolve("/db/data/node").toString());
        assertEquals(401, response.status());
        response = HTTP.withHeaders(HttpHeaders.AUTHORIZATION, challengeResponse("test", "pass"))
                .POST(neo4j.httpURI().resolve("/db/data/transaction/commit").toString(), RO_CYPHER);
        assertEquals(200, response.status());
        response = HTTP.withHeaders(HttpHeaders.AUTHORIZATION, challengeResponse("test", "pass"))
                .POST(neo4j.httpURI().resolve("/db/data/transaction/commit").toString(), RW_CYPHER);
        assertEquals(401, response.status());
        removeUser("test", "pass");
        response = HTTP.withHeaders(HttpHeaders.AUTHORIZATION, challengeResponse("test", "pass"))
                .POST(neo4j.httpURI().resolve("/db/data/node").toString());
        assertEquals(401, response.status());
        response = HTTP.withHeaders(HttpHeaders.AUTHORIZATION, challengeResponse("test", "pass"))
                .GET(neo4j.httpURI().resolve("/db/data").toString());
        assertEquals(401, response.status());
    }

    @Test public void addRwAndRemoveUserTest() throws IOException, InterruptedException {

        addUser("test", "pass", true);

        HTTP.Response response = HTTP.withHeaders(HttpHeaders.AUTHORIZATION, challengeResponse("test", "pass"))
                .GET(neo4j.httpURI().resolve("/").toString());
        assertEquals(200, response.status());
        response = HTTP.withHeaders(HttpHeaders.AUTHORIZATION, challengeResponse("test", "pass"))
                .GET(neo4j.httpURI().resolve("/db/data").toString());
        assertEquals(200, response.status());
        response = HTTP.withHeaders(HttpHeaders.AUTHORIZATION, challengeResponse("test", "pass"))
                .POST(neo4j.httpURI().resolve("/db/data/node").toString());
        assertEquals(201, response.status());
        response = HTTP.withHeaders(HttpHeaders.AUTHORIZATION, challengeResponse("test", "pass"))
                .POST(neo4j.httpURI().resolve("/db/data/transaction/commit").toString(), RO_CYPHER);
        assertEquals(200, response.status());
        response = HTTP.withHeaders(HttpHeaders.AUTHORIZATION, challengeResponse("test", "pass"))
                .POST(neo4j.httpURI().resolve("/db/data/transaction/commit").toString(), RW_CYPHER);
        assertEquals(200, response.status());
        removeUser("test", "pass");
        response = HTTP.withHeaders(HttpHeaders.AUTHORIZATION, challengeResponse("test", "pass"))
                .POST(neo4j.httpURI().resolve("/db/data/node").toString());
        assertEquals(401, response.status());
        response = HTTP.withHeaders(HttpHeaders.AUTHORIZATION, challengeResponse("test", "pass"))
                .GET(neo4j.httpURI().resolve("/db/data").toString());
        assertEquals(401, response.status());
    }

    private String addUser(final String user, String pass, boolean rw) {
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl();
        formData.add("user", user + ":" + pass);
        return HTTP.withHeaders(HttpHeaders.AUTHORIZATION, challengeResponse("neo4j", "master"),HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded")
                .POST(neo4j.httpURI().resolve("admin/add-user-" + (rw ? "rw" : "ro")).toString(), HTTP.RawPayload.rawPayload("user=" + user + ":" + pass)).toString();
    }

    private String removeUser(final String user, String pass) {
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl();
        formData.add("user", user + ":" + pass);
        return HTTP.withHeaders(HttpHeaders.AUTHORIZATION, challengeResponse("neo4j", "master"),HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded")
                .POST(neo4j.httpURI().resolve("admin/remove-user").toString(), HTTP.RawPayload.rawPayload("user=" + user + ":" + pass)).toString();
    }

    private String challengeResponse( String username, String password )
    {
        return "Basic " + base64( username + ":" + password );
    }

    private String base64(String value)
    {
        return UTF8.decode(Base64.encode(value));
    }

    private HTTP.RawPayload RO_CYPHER = HTTP.RawPayload.rawPayload("{\"statements\" : [{\"statement\" : \"MATCH (n) RETURN (n)\"}]}");
    private HTTP.RawPayload RW_CYPHER = HTTP.RawPayload.rawPayload("{\"statements\" : [{\"statement\" : \"CREATE (n) RETURN (n)\"}]}");

}
