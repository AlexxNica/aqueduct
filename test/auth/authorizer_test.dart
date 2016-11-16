import 'package:test/test.dart';
import 'package:aqueduct/aqueduct.dart';
import 'dart:io';
import '../helpers.dart';

void main() {
  ManagedContext context = null;
  AuthDelegate delegate;

  setUp(() async {
    context = await contextWithModels([TestUser, Token, AuthCode]);
    delegate = new AuthDelegate(context);
  });

  tearDown(() async {
    await context?.persistentStore?.close();
    context = null;
  });

  test("fail", () async {
    fail("NYI");
  });

}