part of aqueduct;

/// [RequestController] for issuing OAuth 2.0 authorization codes.
class AuthCodeController extends HTTPController {
  /// Creates a new instance of an [AuthCodeController].
  ///
  /// An [AuthCodeController] requires an [AuthServer] to carry out tasks.
  ///
  /// By default, an [AuthCodeController] has only one [acceptedContentTypes] - 'application/x-www-form-urlencoded'.
  AuthCodeController(this.authenticationServer) {
    acceptedContentTypes = [new ContentType("application", "x-www-form-urlencoded")];
  }

  /// A reference to the [AuthServer] this controller uses to grant authorization codes.
  AuthServer authenticationServer;

  /// Creates a one-time use authorization code.
  ///
  /// The authorization code is returned as a query parameter in the resulting 302 response.
  /// If [state] is supplied, it will be returned in the query as a way
  /// for the client to ensure it is receiving a response from the expected endpoint.
  @httpPost
  Future<Response> authorize({
    @HTTPQuery("client_id") List<String> clientIDs,
    @HTTPQuery("username") List<String> usernames,
    @HTTPQuery("password") List<String> passwords,
    @HTTPQuery("state") List<String> states
  }) async {
    if ((clientIDs?.length ?? 0) == 0) {
      return new Response.badRequest();
    }

    var state = null;
    if ((states?.length ?? 0) > 0) {
      state = states.first;
    }

    if ((clientIDs?.length ?? 0) == 0
    ||  (usernames?.length ?? 0) == 0
    ||  (passwords?.length ?? 0) == 0
    ||  (states?.length ?? 0) > 1
    ||  (clientIDs?.length ?? 0) > 1
    ||  (usernames?.length ?? 0) > 1
    ||  (passwords?.length ?? 0) > 1) {
      var client = null;
      if ((clientIDs?.length ?? 0) == 1) {
        client = await authenticationServer.clientForID(clientIDs.first);
      }
      return errorResponse(client, "invalid_request", state);
    }

    var username = usernames.first;
    var password = passwords.first;
    var clientID = clientIDs.first;

    try {
      var authCode = await authenticationServer.createAuthCode(username, password, clientID);

      return authCodeResponse(authCode, state);
    } on AuthCodeValidationException catch (e) {
      return errorResponse(e?.client, e.message, state);
    }
  }

  static Response authCodeResponse(AuthTokenExchangable authCode, String clientState, {String error: null}) {
    var redirectURI = Uri.parse(authCode.redirectURI);
    Map<String, String> queryParameters = new Map.from(redirectURI.queryParameters);
    queryParameters["code"] = authCode.code;
    if (clientState != null) {
      queryParameters["state"] = clientState;
    }

    return _redirectResponse(redirectURI, queryParameters);
  }

  static Response errorResponse(AuthClient client, String reason, String clientState) {
    if (client?.redirectURI == null) {
      return new Response.badRequest();
    }

    var redirectURI = Uri.parse(client.redirectURI);
    Map<String, String> queryParameters = new Map.from(redirectURI.queryParameters);
    queryParameters["error"] = reason;
    if (clientState != null) {
      queryParameters["state"] = clientState;
    }

    return _redirectResponse(redirectURI, queryParameters);
  }

  static Response _redirectResponse(Uri redirectURI, Map<String, String> queryParameters) {
    var responseURI = new Uri(
        scheme: redirectURI.scheme,
        userInfo: redirectURI.userInfo,
        host: redirectURI.host,
        port: redirectURI.port,
        path: redirectURI.path,
        queryParameters: queryParameters
    );
    return new Response(HttpStatus.MOVED_TEMPORARILY, {"Location": responseURI.toString(), "Cache-Control": "no-store", "Pragma": "no-cache"}, null);
  }

  static Map<int, String> _statusCodeToErrorCodeMap = {
    500 : "server_error",
    503 : "temporarily_unavailable",
    400 : "invalid_request",
    401 : "access_denied"
  };

  @override
  List<APIResponse> documentResponsesForOperation(APIOperation operation) {
    var responses = super.documentResponsesForOperation(operation);
    if (operation.id == APIOperation.idForMethod(this, #authorize)) {
      responses.addAll([
        new APIResponse()
          ..statusCode = HttpStatus.MOVED_TEMPORARILY
          ..description = "Successfully issued an authorization code.",
        new APIResponse()
          ..statusCode = HttpStatus.BAD_REQUEST
          ..description = "Missing one or more of: 'client_id', 'username', 'password'.",
        new APIResponse()
          ..statusCode = HttpStatus.UNAUTHORIZED
          ..description = "Not authorized",
      ]);
    }

    return responses;
  }
}
