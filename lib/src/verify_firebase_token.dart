import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:jose/jose.dart';

import 'firebase_jwt.dart';
import 'firebase_verify_exception.dart';

/// Verifies a Firebase auth JWT and returns the decoded token.
///
/// You need to pass the [token] that needs to be verified. Apart from that
/// the verification requires the `projectId` of your Firebase project as well.
/// This can be provided in multiple ways. You can pass the [projectId]
/// argument directly.
///
/// If you have a `service-account.json` file in your project, you can pass
/// the path to this file with [serviceFilePath]. If you don't pass anything
/// `File('service-account.json')` will be tried.
///
/// You only need to pass either the [projectId] or the [serviceFilePath].
///
/// **With project id:**
/// ```dart
/// final jwt = await verifyFirebaseToken('ey...', projectId: 'my-project-id');
/// ```
///
/// **With service file at the root:**
/// ```dart
/// final jwt = await verifyFirebaseToken('ey...');
/// ```
///
/// **With service account file:**
/// ```dart
/// final jwt = await verifyFirebaseToken('ey...', serviceFilePath: 'path/to/service-account.json');
/// ```
Future<FirebaseJWT> verifyFirebaseToken(
  String token, {
  String? projectId,
  String? serviceFilePath,
}) async {
  final projectIdentifier =
      projectId ?? (await _getProjectIdFromServiceFile(serviceFilePath));
  if (projectIdentifier == null) {
    throw FirebaseVerifyException('Project identifier missing');
  }

  final decodedHeaders = _getDecodedHeaders(token);
  final unverifiedToken = JsonWebToken.unverified(token);
  final decodedPayload = unverifiedToken.claims.toJson();

  if (decodedHeaders['alg'] != 'RS256') {
    throw FirebaseVerifyException('Wrong algorithm');
  }

  final kid = decodedHeaders['kid'];
  if (kid == null) {
    throw FirebaseVerifyException('No kid available');
  }

  final certificate = await _getCertificateByKid(kid);
  if (certificate == null) {
    throw FirebaseVerifyException('No certificate found matching with kid');
  }

  final currentDateInSeconds = DateTime.now().millisecondsSinceEpoch / 1000;

  final int? expiryDate = decodedPayload['exp'];
  final int? issuedAt = decodedPayload['iat'];
  final int? authTime = decodedPayload['auth_time'];
  final String? audience = decodedPayload['aud'];
  final String? issuer = decodedPayload['iss'];
  final String? subject = decodedPayload['sub'];

  if (expiryDate == null) {
    throw FirebaseVerifyException('Missing expiry date');
  }

  if (expiryDate < currentDateInSeconds) {
    throw FirebaseVerifyException('Token expired');
  }

  if (authTime == null) {
    throw FirebaseVerifyException('Missing auth time');
  }

  if (authTime > currentDateInSeconds) {
    throw FirebaseVerifyException('Authenticated in the future');
  }

  if (issuedAt == null) {
    throw FirebaseVerifyException('Missing issued date');
  }

  if (issuedAt > currentDateInSeconds) {
    throw FirebaseVerifyException('Token issued in the future');
  }

  if (audience != projectIdentifier) {
    throw FirebaseVerifyException('Wrong audience');
  }

  if (issuer != 'https://securetoken.google.com/$projectIdentifier') {
    throw FirebaseVerifyException('Wrong issuer');
  }

  if (subject == null) {
    throw FirebaseVerifyException('Subject data missing');
  }

  final keyStore = JsonWebKeyStore()
    ..addKey(JsonWebKey.fromPem(
      certificate,
      keyId: kid,
    ));
  var verified = await unverifiedToken.verify(keyStore);
  if (!verified) {
    throw FirebaseVerifyException('The token signature is invalid');
  }

  return FirebaseJWT(
    headers: decodedHeaders,
    payload: unverifiedToken.claims.toJson(),
  );
}

/// Returns the decoded header data from the token.
Map<String, dynamic> _getDecodedHeaders(String token) {
  final splitToken = token.split('.');
  if (splitToken.length != 3) {
    throw FirebaseVerifyException('Invalid token');
  }

  final normalizedHeader = base64.normalize(splitToken[0]);
  final headerString = utf8.decode(base64.decode(normalizedHeader));
  final decodedHeader = jsonDecode(headerString) as Map<String, dynamic>;

  return decodedHeader;
}

/// Retrives the project id from the service account file.
/// Optionally you can pass the [serviceFilePath] to the function, but if
/// not, it will try to get the file as `File('service-account.json')`.
Future<String?> _getProjectIdFromServiceFile(String? serviceFilePath) async {
  final file = File(serviceFilePath ?? 'service-account.json');
  if (!(await file.exists())) {
    throw FirebaseVerifyException('No service account json file found');
  }

  final dynamic serviceAccountJson = jsonDecode(await file.readAsString());
  return serviceAccountJson['project_id'] as String?;
}

var httpClient = http.Client();

/// Url for the x509 certificates that are used as the public keys.
const certificateUrl =
    'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';

/// Retrieves the current certificates from the [certificateUrl], defined by
/// [Firebase](https://firebase.google.com/docs/auth/admin/verify-id-tokens).
/// Matches the [kid] header of the JWT with the certificates and returns the
/// match.
Future<String?> _getCertificateByKid(String kid) async {
  final certsRaw = await httpClient.read(Uri.parse(certificateUrl));
  final dynamic data = jsonDecode(certsRaw);

  final kidCertificate = data[kid] as String?;
  return kidCertificate;
}
