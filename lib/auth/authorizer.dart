part of aqueduct;

/// The type of authentication strategy to use for an [Authorizer].
enum AuthStrategy {
  /// The resource owner strategy requires that a [Request] have a Bearer token.
  resourceOwner,

  /// The client strategy requires that the [Request] have a Basic Authorization Client ID and Client secret.
  client
}

/// A [RequestController] that will authorize further passage in a [RequestController] chain when appropriate credentials
/// are provided in the request being handled.
///
/// An instance of [Authorizer] will validate a [Request] given a [strategy] with its [server].
/// If the [Request] is unauthorized, it will respond with the appropriate status code and prevent
/// further request processing. If the [Request] is valid, it will attach a [Authorization]
/// to the [Request] and deliver it to the next [RequestController].
class Authorizer extends RequestController {
  /// Creates an instance of [Authorizer] with a reference back to its [server] and a [strategy].
  ///
  /// The default strategy is [AuthStrategy.resourceOwner]. By default, [acceptableClientIDs] is null and therefore all client IDs are accepted
  /// when [strategy] is [AuthStrategy.client].
  Authorizer(this.server, {this.strategy: AuthStrategy.resourceOwner, this.acceptableClientIDs: null}) {
    policy = null;
  }

  /// Creates an instance of [Authorizer] with [AuthStrategy.resourceOwner].
  Authorizer.resourceOwner(AuthServer server) : this(server, strategy: AuthStrategy.resourceOwner);

  /// Creates an instance of [Authorizer] with [AuthStrategy.client].
  ///
  /// [acceptOnly] will set the [acceptableClientIDs] of this instance.
  Authorizer.client(AuthServer server, {List<String> acceptOnly: null}) : this(server, strategy: AuthStrategy.client, acceptableClientIDs: acceptOnly);

  /// A reference to the [AuthServer] for which this [Authorizer] belongs to.
  AuthServer server;

  /// The [AuthStrategy] for authenticating a request.
  AuthStrategy strategy;

  /// The list of acceptable client IDs for client strategy authorizers.
  ///
  /// By default, this value is null and therefore accepts all client IDs. By setting this value to
  /// a specific set of case-sensitive client IDs, only requests with matching a client ID in
  /// their Authorization header may pass through this instance. This value has no impact on
  /// instances where [strategy] is [AuthStrategy.resourceOwner].
  List<String> acceptableClientIDs;

  @override
  Future<RequestControllerEvent> processRequest(Request req) async {
    var errorResponse = null;
    if (strategy == AuthStrategy.resourceOwner) {
      var result = _processResourceOwnerRequest(req);
      if (result is Request) {
        return result;
      }

      errorResponse = result;
    } else if (strategy == AuthStrategy.client) {
      var result = _processClientRequest(req);
      if (result is Request) {
        return result;
      }

      errorResponse = result;
    }

    if (errorResponse == null) {
      errorResponse = new Response.serverError();
    }
    
    return errorResponse;
  }

  Future<RequestControllerEvent> _processResourceOwnerRequest(Request req) async {
    var bearerToken = AuthorizationBearerParser.parse(req.innerRequest.headers.value(HttpHeaders.AUTHORIZATION));
    var permission = await server.verify(bearerToken);

    req.authorization = permission;

    return req;
  }

  Future<RequestControllerEvent> _processClientRequest(Request req) async {
    var parser = AuthorizationBasicParser.parse(req.innerRequest.headers.value(HttpHeaders.AUTHORIZATION));

    if (acceptableClientIDs != null && !acceptableClientIDs.contains(parser.username)) {
      return new Response.unauthorized();
    }

    var client = await server.clientForID(parser.username);
    if (client == null) {
      return new Response.unauthorized();
    }

    if (client.hashedSecret != AuthServer.generatePasswordHash(parser.password, client.salt)) {
      return new Response.unauthorized();
    }

    var perm = new Authorization(client.id, null, server);
    req.authorization = perm;

    return req;
  }


  @override
  List<APIOperation> documentOperations(PackagePathResolver resolver) {
    List<APIOperation> items = nextController.documentOperations(resolver);

    var secReq= new APISecurityRequirement()
      ..scopes = [];

    if (strategy == AuthStrategy.client) {
      secReq.name = "oauth2.application";
    } else if (strategy == AuthStrategy.resourceOwner) {
      secReq.name = "oauth2.password";
    }

    items.forEach((i) {
      i.security = [secReq];
    });

    return items;
  }
}
