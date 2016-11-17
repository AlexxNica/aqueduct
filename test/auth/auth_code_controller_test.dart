import 'package:test/test.dart';
import 'dart:io';
import 'package:aqueduct/aqueduct.dart';
import '../helpers.dart';

void main() {
  Application<TestSink> application = new Application<TestSink>();
  TestClient client = new TestClient.onPort(8080)
    ..clientID = "com.stablekernel.app3"
    ..clientSecret = "mckinley";

  tearDownAll(() async {
    await application?.stop();
  });

  setUpAll(() async {
    await contextWithModels([TestUser, Token, AuthCode]);
    await application.start(runOnMainIsolate: true);

    await createUsers(2);
  });

  test("POST code responds with auth code on correct input", () async {
    var req = client.clientAuthenticatedRequest("/auth/code")
        ..formData = {
          "client_id" : "com.stablekernel.app3",
          "username" : "bob+0@stablekernel.com",
          "password" : "foobaraxegrind21%"
        };
    var res = await req.post();

    expect(res, hasStatus(HttpStatus.MOVED_TEMPORARILY));

    var location = res.headers.value(HttpHeaders.LOCATION);
    var uri = Uri.parse(location);

    expect(uri.queryParameters["code"], hasLength(greaterThan(0)));
    expect(uri.queryParameters["state"], isNull);
    expect(uri.host, equals("stablekernel.com"));
    expect(uri.path, equals("/auth/redirect"));
  });

  test("POST code responds with auth code and state", () async {
    var req = client.clientAuthenticatedRequest("/auth/code")
      ..formData = {
        "client_id" : "com.stablekernel.app3",
        "username" : "bob+0@stablekernel.com",
        "password" : "foobaraxegrind21%",
        "state" : "Alaska"
      };
    var res = await req.post();

    expect(res, hasStatus(HttpStatus.MOVED_TEMPORARILY));

    var location = res.headers.value(HttpHeaders.LOCATION);
    var uri = Uri.parse(location);

    expect(uri.queryParameters["code"], hasLength(greaterThan(0)));
    expect(uri.queryParameters["state"], equals("Alaska"));
    expect(uri.host, equals("stablekernel.com"));
    expect(uri.path, equals("/auth/redirect"));
  });

  test("POST fails because client doesn't have a redirect URI", () async {
    var req = client.clientAuthenticatedRequest("/auth/code")
      ..formData = {
        "client_id" : "com.stablekernel.app1",
        "username" : "bob+0@stablekernel.com",
        "password" : "foobaraxegrind21%",
      };
    var res = await req.post();
    expect(res, hasStatus(400));
  });

  test("POST fails if client identifier is missing", () async {
    var req = client.request("/auth/code")
      ..formData = {
        "username" : "bob+0@stablekernel.com",
        "password" : "foobaraxegrind21%"
      };

    var res = await req.post();
    expect(res, hasStatus(400));
    expect(res.headers.value(HttpHeaders.LOCATION), isNull);
  });

  test("POST fails if client identifier is invalid", () async {
    var req = client.request("/auth/code")
      ..formData = {
        "client_id" : "com.stablekpp3",
        "username" : "bob+0@stablekernel.com",
        "password" : "foobaraxegrind21%"
      };

    var res = await req.post();
    expect(res, hasStatus(400));
    expect(res.headers.value(HttpHeaders.LOCATION), isNull);
  });

  test("POST fails because required parameter is omitted", () async {
    // Omit username
    var req = client.request("/auth/code")
      ..formData = {
        "client_id" : "com.stablekernel.app3",
        "password" : "foobaraxegrind21%"
      };
    var res = await req.post();
    expect(res, hasStatus(HttpStatus.MOVED_TEMPORARILY));
    var location = res.headers.value(HttpHeaders.LOCATION);
    var uri = Uri.parse(location);

    expect(uri.queryParameters["code"], isNull);
    expect(uri.queryParameters["state"], isNull);
    expect(uri.queryParameters["error"], equals("invalid_request"));
    expect(uri.host, equals("stablekernel.com"));
    expect(uri.path, equals("/auth/redirect"));

    req = client.request("/auth/code")
      ..formData = {
        "client_id" : "com.stablekernel.app3",
        "password" : "foobaraxegrind21%",
        "state" : "Alaska"
      };
    res = await req.post();
    expect(res, hasStatus(HttpStatus.MOVED_TEMPORARILY));
    location = res.headers.value(HttpHeaders.LOCATION);
    uri = Uri.parse(location);

    expect(uri.queryParameters["code"], isNull);
    expect(uri.queryParameters["state"], equals("Alaska"));
    expect(uri.queryParameters["error"], equals("invalid_request"));
    expect(uri.host, equals("stablekernel.com"));
    expect(uri.path, equals("/auth/redirect"));

    // Omit password
    req = client.request("/auth/code")
      ..formData = {
        "client_id" : "com.stablekernel.app3",
        "username" : "bob+0@stablekernel.com",
      };
    res = await req.post();
    expect(res, hasStatus(HttpStatus.MOVED_TEMPORARILY));
    location = res.headers.value(HttpHeaders.LOCATION);
    uri = Uri.parse(location);

    expect(uri.queryParameters["code"], isNull);
    expect(uri.queryParameters["state"], isNull);
    expect(uri.queryParameters["error"], equals("invalid_request"));
    expect(uri.host, equals("stablekernel.com"));
    expect(uri.path, equals("/auth/redirect"));

    req = client.request("/auth/code")
      ..formData = {
        "client_id" : "com.stablekernel.app3",
        "username" : "bob+0@stablekernel.com",
        "state" : "Alaska"
      };
    res = await req.post();
    expect(res, hasStatus(HttpStatus.MOVED_TEMPORARILY));
    location = res.headers.value(HttpHeaders.LOCATION);
    uri = Uri.parse(location);

    expect(uri.queryParameters["code"], isNull);
    expect(uri.queryParameters["state"], equals("Alaska"));
    expect(uri.queryParameters["error"], equals("invalid_request"));
    expect(uri.host, equals("stablekernel.com"));
    expect(uri.path, equals("/auth/redirect"));
  });

  test("POST fails because parameter value is included more than once", () async {
    // Include username twice
    var req = client.request("/auth/code")
      ..contentType = new ContentType("application", "x-www-form-urlencoded")
      ..body = "client_id=com.stablekernel.app3&username=abcd&password=abc&username=abcd";

    var res = await req.post();
    expect(res, hasStatus(HttpStatus.MOVED_TEMPORARILY));
    var location = res.headers.value(HttpHeaders.LOCATION);
    var uri = Uri.parse(location);

    expect(uri.queryParameters["code"], isNull);
    expect(uri.queryParameters["state"], isNull);
    expect(uri.queryParameters["error"], equals("invalid_request"));
    expect(uri.host, equals("stablekernel.com"));
    expect(uri.path, equals("/auth/redirect"));

    // Include client_id twice
    req = client.request("/auth/code")
      ..contentType = new ContentType("application", "x-www-form-urlencoded")
      ..body = "client_id=com.stablekernel.app3&username=abcd&password=abc&client_id=abcd&state=bar";

    res = await req.post();
    expect(res, hasStatus(HttpStatus.BAD_REQUEST));
    expect(res.headers.value(HttpHeaders.LOCATION), isNull);

    // Include password twice
    req = client.request("/auth/code")
      ..contentType = new ContentType("application", "x-www-form-urlencoded")
      ..body = "client_id=com.stablekernel.app3&username=abcd&password=abc&password=abcd";

    res = await req.post();
    expect(res, hasStatus(HttpStatus.MOVED_TEMPORARILY));
    location = res.headers.value(HttpHeaders.LOCATION);
    uri = Uri.parse(location);

    expect(uri.queryParameters["code"], isNull);
    expect(uri.queryParameters["state"], isNull);
    expect(uri.queryParameters["error"], equals("invalid_request"));
    expect(uri.host, equals("stablekernel.com"));
    expect(uri.path, equals("/auth/redirect"));

    // Include state twice
    req = client.request("/auth/code")
      ..contentType = new ContentType("application", "x-www-form-urlencoded")
      ..body = "client_id=com.stablekernel.app3&username=abcd&password=abc&state=abcd&state=foo";

    res = await req.post();
    expect(res, hasStatus(HttpStatus.MOVED_TEMPORARILY));
    location = res.headers.value(HttpHeaders.LOCATION);
    uri = Uri.parse(location);

    expect(uri.queryParameters["code"], isNull);
    expect(uri.queryParameters["state"], equals("abcd"));
    expect(uri.queryParameters["error"], equals("invalid_request"));
    expect(uri.host, equals("stablekernel.com"));
    expect(uri.path, equals("/auth/redirect"));
  });

  test("POST fails because access is denied", () async {
    // Bad username
    var req = client.request("/auth/code")
      ..formData = {
        "client_id" : "com.stablekernel.app3",
        "username" : "bob+0@stcom",
        "password" : "foobaraxegrind21%"
      };
    var res = await req.post();
    expect(res, hasStatus(HttpStatus.MOVED_TEMPORARILY));
    var location = res.headers.value(HttpHeaders.LOCATION);
    var uri = Uri.parse(location);

    expect(uri.queryParameters["code"], isNull);
    expect(uri.queryParameters["state"], isNull);
    expect(uri.queryParameters["error"], equals("access_denied"));
    expect(uri.host, equals("stablekernel.com"));
    expect(uri.path, equals("/auth/redirect"));

    req = client.request("/auth/code")
      ..formData = {
        "client_id" : "com.stablekernel.app3",
        "username" : "bob+0@stcom",
        "password" : "foobaraxegrind21%",
        "state" : "Alaska"
      };
    res = await req.post();
    expect(res, hasStatus(HttpStatus.MOVED_TEMPORARILY));
    location = res.headers.value(HttpHeaders.LOCATION);
    uri = Uri.parse(location);

    expect(uri.queryParameters["code"], isNull);
    expect(uri.queryParameters["state"], equals("Alaska"));
    expect(uri.queryParameters["error"], equals("access_denied"));
    expect(uri.host, equals("stablekernel.com"));
    expect(uri.path, equals("/auth/redirect"));

    // Bad password
    req = client.request("/auth/code")
      ..formData = {
        "client_id" : "com.stablekernel.app3",
        "username" : "bob+0@stablekernel.com",
        "password" : "fooba%"
      };
    res = await req.post();
    expect(res, hasStatus(HttpStatus.MOVED_TEMPORARILY));
    location = res.headers.value(HttpHeaders.LOCATION);
    uri = Uri.parse(location);

    expect(uri.queryParameters["code"], isNull);
    expect(uri.queryParameters["state"], isNull);
    expect(uri.queryParameters["error"], equals("access_denied"));
    expect(uri.host, equals("stablekernel.com"));
    expect(uri.path, equals("/auth/redirect"));

    req = client.request("/auth/code")
      ..formData = {
        "client_id" : "com.stablekernel.app3",
        "username" : "bob+0@stablekernel.com",
        "password" : "fooba%",
        "state" : "Alaska"
      };
    res = await req.post();
    expect(res, hasStatus(HttpStatus.MOVED_TEMPORARILY));
    location = res.headers.value(HttpHeaders.LOCATION);
    uri = Uri.parse(location);

    expect(uri.queryParameters["code"], isNull);
    expect(uri.queryParameters["state"], equals("Alaska"));
    expect(uri.queryParameters["error"], equals("access_denied"));
    expect(uri.host, equals("stablekernel.com"));
    expect(uri.path, equals("/auth/redirect"));
  });

  test("POST exchange auth code for token", () async {
    var codeRequest = client.clientAuthenticatedRequest("/auth/code")
      ..formData = {
        "client_id" : "com.stablekernel.app3",
        "username" : "bob+0@stablekernel.com",
        "password" : "foobaraxegrind21%"
      };
    var codeResponse = await codeRequest.post();
    var location = codeResponse.headers.value(HttpHeaders.LOCATION);
    var uri = Uri.parse(location);
    var code = uri.queryParameters["code"];

    var tokenRequest = client.clientAuthenticatedRequest("/auth/token")
      ..formData = {
        "grant_type" : "authorization_code",
        "authorization_code": code
      };
    var tokenResponse = await tokenRequest.post();

    expect(tokenResponse, hasResponse(200, {
      "access_token" : hasLength(greaterThan(0)),
      "refresh_token" : hasLength(greaterThan(0)),
      "expires_in" : greaterThan(3500),
      "token_type" : "bearer"
    }));
  });

  test("POST exchange with bad header fails", () async {
    var codeRequest = client.clientAuthenticatedRequest("/auth/code")
      ..formData = {
        "client_id" : "com.stablekernel.app3",
        "username" : "bob+0@stablekernel.com",
        "password" : "foobaraxegrind21%"
      };
    var codeResponse = await codeRequest.post();
    var location = codeResponse.headers.value(HttpHeaders.LOCATION);
    var uri = Uri.parse(location);
    var code = uri.queryParameters["code"];
    var formData = {
      "grant_type" : "authorization_code",
      "authorization_code": code
    };

    var req = client.request("/auth/token")
      ..formData = formData;
    expect(await req.post(), hasStatus(400), reason: "omit authorization header");

    req = client.request("/auth/token")
      ..headers = {"Authorization" : "foobar"}
      ..formData = formData;
    expect(await req.post(), hasStatus(400), reason: "omit 'Basic'");

    // Non-base64 data
    req = client.request("/auth/token")
      ..headers = {"Authorization" : "Basic bad"}
      ..formData = formData;
    expect(await req.post(), hasStatus(400), reason: "Non-base64 data");

    // Wrong thing
    req = client.clientAuthenticatedRequest("/auth/token", clientID: "foobar")
      ..formData = formData;
    expect(await req.post(), hasStatus(401), reason: "Wrong client id");
  });

  test("POST exchange with bad body fails", () async {
    var codeRequest = client.clientAuthenticatedRequest("/auth/code")
      ..formData = {
        "client_id" : "com.stablekernel.app3",
        "username" : "bob+0@stablekernel.com",
        "password" : "foobaraxegrind21%"
      };
    var codeResponse = await codeRequest.post();
    var location = codeResponse.headers.value(HttpHeaders.LOCATION);
    var uri = Uri.parse(location);
    var code = uri.queryParameters["code"];

    // Missing grant_type
    var req = client.clientAuthenticatedRequest("/auth/token")
      ..formData = {
        "authorization_code": code
      };
    expect(await req.post(), hasStatus(400));

    // Invalid grant_type
    req = client.clientAuthenticatedRequest("/auth/token")
      ..formData = {
        "grant_type" : "auth_code",
        "authorization_code": code
      };
    expect(await req.post(), hasStatus(400));

    // Omit auth code
    req = client.clientAuthenticatedRequest("/auth/token")
      ..formData = {
        "grant_type" : "authorization_code"
      };
    expect(await req.post(), hasStatus(400));

    // Invalid auth code
    req = client.clientAuthenticatedRequest("/auth/token")
      ..formData = {
        "grant_type" : "authorization_code",
        "authorization_code": "bogus"
      };
    expect(await req.post(), hasStatus(401));
  });

  test("Response documentation", () {
    AuthCodeController ac = new AuthCodeController(new AuthServer(new AuthDelegate(ManagedContext.defaultContext)));
    var resolver = new PackagePathResolver(new File(".packages").path);
    var operations = ac.documentOperations(resolver);

    expect(operations.length, 1);

    List<APIResponse> responses = ac.documentResponsesForOperation(operations.first);
    expect(responses.any((ar) => ar.key == "${HttpStatus.MOVED_TEMPORARILY}"), true);
    expect(responses.any((ar) => ar.key == "${HttpStatus.BAD_REQUEST}"), true);
    expect(responses.any((ar) => ar.key == "${HttpStatus.INTERNAL_SERVER_ERROR}"), true);
    expect(responses.any((ar) => ar.key == "${HttpStatus.UNAUTHORIZED}"), true);
  });
}

class TestSink extends RequestSink {
  TestSink(Map<String, dynamic> opts) : super(opts) {
    authServer = new AuthServer<TestUser, Token, AuthCode>(new AuthDelegate(ManagedContext.defaultContext));
  }

  AuthServer authServer;

  void setupRouter(Router router) {
    router
        .route("/auth/code")
        .generate(() => new AuthCodeController(authServer));
    router
        .route("/auth/token")
        .generate(() => new AuthController(authServer));
  }
}

