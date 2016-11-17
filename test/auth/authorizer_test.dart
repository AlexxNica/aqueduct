import 'package:test/test.dart';
import 'package:aqueduct/aqueduct.dart';
import 'dart:io';
import '../helpers.dart';
import 'dart:async';
import 'package:http/http.dart' as http;
import 'dart:convert';

void main() {
  ManagedContext context = null;
  AuthDelegate delegate;
  AuthServer authServer;
  HttpServer server;
  String accessToken;
  String expiredErrorToken;

  setUp(() async {
    context = await contextWithModels([TestUser, Token, AuthCode]);
    delegate = new AuthDelegate(context);
    authServer = new AuthServer<TestUser, Token, AuthCode>(delegate);
    var u = (await createUsers(1)).first;

    accessToken = (await authServer.authenticate("bob+0@stablekernel.com", "foobaraxegrind21%", "com.stablekernel.app1", "kilimanjaro")).accessToken;
    expiredErrorToken = (await authServer.authenticate("bob+0@stablekernel.com", "foobaraxegrind21%", "com.stablekernel.app1", "kilimanjaro", expirationInSeconds: 0)).accessToken;
  });

  tearDown(() async {
    await context?.persistentStore?.close();
    context = null;

    await server?.close();
  });

  test("No bearer token returns 401", () async {
    var authorizer = new Authorizer(authServer);
    server = await enableAuthorizer(authorizer);

    var res = await http.get("http://localhost:8000");
    expect(res.statusCode, 401);
    expect(JSON.decode(res.body), {"error" : "No authorization header."});
  });

  test("Malformed authorization bearer header returns 401", () async {
    var authorizer = new Authorizer(authServer);
    server = await enableAuthorizer(authorizer);

    var res = await http.get("http://localhost:8000", headers: {"Authorization" : "Notbearer"});
    expect(res.statusCode, 401);
    expect(JSON.decode(res.body), {"error" : "Improper authorization header."});
  });

  test("Malformed, but close, authorization bearer header returns 401", () async {
    var authorizer = new Authorizer(authServer);
    server = await enableAuthorizer(authorizer);

    var res = await http.get("http://localhost:8000", headers: {"Authorization" : "Bearer "});
    expect(res.statusCode, 401);
    expect(JSON.decode(res.body), {"error" : "Improper authorization header."});
  });

  test("Invalid bearer token returns 401", () async {
    var authorizer = new Authorizer(authServer);
    server = await enableAuthorizer(authorizer);

    var res = await http.get("http://localhost:8000", headers: {"Authorization" : "Bearer 1234567890asdfghjkl"});
    expect(res.statusCode, 401);
    expect(JSON.decode(res.body), {"error" : "Invalid Token"});
  });

  test("Expired bearer token returns 401", () async {
    var authorizer = new Authorizer.resourceOwner(authServer);
    server = await enableAuthorizer(authorizer);

    var res = await http.get("http://localhost:8000", headers: {"Authorization" : "Bearer $expiredErrorToken"});
    expect(res.statusCode, 401);
    expect(JSON.decode(res.body), {"error" : "Expired token"});
  });

  test("Valid bearer token returns authorization object", () async {
    var authorizer = new Authorizer(authServer);
    server = await enableAuthorizer(authorizer);

    var res = await http.get("http://localhost:8000", headers: {"Authorization" : "Bearer $accessToken"});
    expect(res.statusCode, 200);
    expect(JSON.decode(res.body), {"clientID" : "com.stablekernel.app1", "resourceOwnerIdentifier" : 1});
  });

  test("No basic auth header returns 401", () async {
    var authorizer = new Authorizer.client(authServer);
    server = await enableAuthorizer(authorizer);

    var res = await http.get("http://localhost:8000");
    expect(res.statusCode, 401);
    expect(JSON.decode(res.body), {"error" : "No authorization header."});
  });

  test("Malformed basic authorization header returns 401", () async {
    var authorizer = new Authorizer.client(authServer);
    server = await enableAuthorizer(authorizer);

    var res = await http.get("http://localhost:8000", headers: {"Authorization" : "Notright"});
    expect(res.statusCode, 401);
    expect(JSON.decode(res.body), {"error" : "Improper authorization header."});
  });

  test("Malformed basic authorization, but empty, header returns 401", () async {
    var authorizer = new Authorizer.client(authServer);
    server = await enableAuthorizer(authorizer);

    var res = await http.get("http://localhost:8000", headers: {"Authorization" : "Basic "});
    expect(res.statusCode, 401);
    expect(JSON.decode(res.body), {"error" : "Improper authorization header."});
  });

  test("Malformed basic authorization, but bad data, header returns 401", () async {
    var authorizer = new Authorizer.client(authServer);
    server = await enableAuthorizer(authorizer);

    var res = await http.get("http://localhost:8000", headers: {"Authorization" : "Basic asasd"});
    expect(res.statusCode, 401);
    expect(JSON.decode(res.body), {"error" : "Improper authorization header."});
  });

  test("Valid client ID, but not accepted by authorizer returns 401", () async {
    var authorizer = new Authorizer.client(authServer, acceptOnly: ["com.stablekernel.app2"]);
    server = await enableAuthorizer(authorizer);

    var res = await http.get("http://localhost:8000", headers: {"Authorization" : "Basic ${new Base64Encoder().convert("com.stablekernel.app1:kilimanjaro".codeUnits)}"});
    expect(res.statusCode, 401);
    expect(res.body, "");
  });

  test("Valid client ID, but ONLY accepted by authorizer returns 200 with authorization", () async {
    var authorizer = new Authorizer.client(authServer, acceptOnly: ["com.stablekernel.app1"]);
    server = await enableAuthorizer(authorizer);

    var res = await http.get("http://localhost:8000", headers: {"Authorization" : "Basic ${new Base64Encoder().convert("com.stablekernel.app1:kilimanjaro".codeUnits)}"});
    expect(res.statusCode, 200);
    expect(JSON.decode(res.body), {"clientID" : "com.stablekernel.app1", "resourceOwnerIdentifier" : null});
  });

  test("Invalid client id returns 401", () async {
    var authorizer = new Authorizer.client(authServer);
    server = await enableAuthorizer(authorizer);

    var res = await http.get("http://localhost:8000", headers: {"Authorization" : "Basic ${new Base64Encoder().convert("abcd:kilimanjaro".codeUnits)}"});
    expect(res.statusCode, 401);
    expect(res.body, "");
  });

  test("Invalid client secret returns 401", () async {
    var authorizer = new Authorizer.client(authServer);
    server = await enableAuthorizer(authorizer);

    var res = await http.get("http://localhost:8000", headers: {"Authorization" : "Basic ${new Base64Encoder().convert("com.stablekernel.app1:foobar".codeUnits)}"});
    expect(res.statusCode, 401);
    expect(res.body, "");
  });

  test("Valid client ID returns 200 with authorization", () async {
    var authorizer = new Authorizer.client(authServer);
    server = await enableAuthorizer(authorizer);

    var res = await http.get("http://localhost:8000", headers: {"Authorization" : "Basic ${new Base64Encoder().convert("com.stablekernel.app1:kilimanjaro".codeUnits)}"});
    expect(res.statusCode, 200);
    expect(JSON.decode(res.body), {"clientID" : "com.stablekernel.app1", "resourceOwnerIdentifier" : null});
  });

}

Future<HttpServer> enableAuthorizer(Authorizer authorizer) async {
  var router = new Router();
  router.route("/").pipe(authorizer).listen(respond);
  router.finalize();

  var server = await HttpServer.bind(InternetAddress.ANY_IP_V4, 8000);
  server.map((httpReq) => new Request(httpReq)).listen(router.receive);

  return server;
}


Future<RequestControllerEvent> respond(Request req) async {
  var m = {};

  m["clientID"] = req.authorization.clientID;
  m["resourceOwnerIdentifier"] = req.authorization.resourceOwnerIdentifier;

  return new Response.ok(m);
}