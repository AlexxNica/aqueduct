import 'package:aqueduct/aqueduct.dart';
import 'package:test/test.dart';
import 'dart:io';
import 'dart:async';

Future main() async {
  TestClient client = new TestClient(8080);
  HttpServer server = null;

  setUpAll(() async {
    server = await HttpServer.bind("localhost", 8080, v6Only: false, shared: false);
    server.listen((req) {
      var resReq = new ResourceRequest(req);
      var controller = new TestController();
      controller.deliver(resReq);
    });
  });

  tearDownAll(() async {
    await server?.close(force: true);
  });

  test("Client can expect array of JSON", () async {
    var resp = await client.request("/na").get();
    expect(resp, hasResponse(200, [], matchesJSON([{
      "id" : greaterThan(0)
    }])));
  });
}

class TestController extends HttpController {
  @httpGet get() async {
    return new Response.ok([{"id" : 1}, {"id" : 2}]);
  }
}