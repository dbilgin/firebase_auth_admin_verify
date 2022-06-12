import 'package:firebase_auth_admin_verify/firebase_auth_admin_verify.dart';
import 'package:http/http.dart' as http;
import 'package:jose/jose.dart';
import 'package:mocktail/mocktail.dart';
import 'package:test/test.dart';

class MockClient extends Mock implements http.Client {}

JsonWebSignatureBuilder _getBuilder({bool isHS256 = false}) {
  final builder = JsonWebSignatureBuilder();
  if (!isHS256) {
    builder.addRecipient(JsonWebKey.fromPem(_privateKey));
  } else {
    builder.addRecipient(
      JsonWebKey.fromJson({
        'kty': 'oct',
        'k':
            'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow'
      }),
      algorithm: 'HS256',
    );
  }
  return builder;
}

void main() {
  final client = MockClient();

  final dateInTheFuture =
      DateTime.now().add(Duration(minutes: 3)).millisecondsSinceEpoch ~/ 1000;
  final dateInThePast =
      DateTime.now().add(Duration(minutes: -3)).millisecondsSinceEpoch ~/ 1000;
  final kid = 'my-kid';
  setUpAll(() {
    httpClient = client;
  });

  group('Exceptions:', () {
    test('service account file', () {
      var claims = JsonWebTokenClaims.fromJson({});
      final builder = _getBuilder();
      builder.jsonContent = claims.toJson();
      final token = builder.build();

      expect(
        verifyFirebaseToken(token.toCompactSerialization()),
        throwsA(
          predicate(
            (e) =>
                e is FirebaseVerifyException &&
                e.message == 'No service account json file found',
          ),
        ),
      );
    });

    test('invalid token', () {
      var claims = JsonWebTokenClaims.fromJson({});
      final builder = _getBuilder();
      builder.jsonContent = claims.toJson();
      final token = builder.build();
      final splitToken = token.toCompactSerialization().split('.');

      expect(
        verifyFirebaseToken(
          '${splitToken[0]}.${splitToken[1]}',
          projectId: 'my-project-id',
        ),
        throwsA(
          predicate(
            (e) => e is FirebaseVerifyException && e.message == 'Invalid token',
          ),
        ),
      );
    });

    test('wrong algorithm', () {
      var claims = JsonWebTokenClaims.fromJson({});
      final builder = _getBuilder(isHS256: true);
      builder.jsonContent = claims.toJson();
      final token = builder.build();

      expect(
        verifyFirebaseToken(
          token.toCompactSerialization(),
          projectId: 'my-project-id',
        ),
        throwsA(
          predicate(
            (e) =>
                e is FirebaseVerifyException && e.message == 'Wrong algorithm',
          ),
        ),
      );
    });

    test('no kid', () {
      var claims = JsonWebTokenClaims.fromJson({});
      final builder = _getBuilder();
      builder.jsonContent = claims.toJson();
      final token = builder.build();

      expect(
        verifyFirebaseToken(
          token.toCompactSerialization(),
          projectId: 'my-project-id',
        ),
        throwsA(
          predicate(
            (e) =>
                e is FirebaseVerifyException && e.message == 'No kid available',
          ),
        ),
      );
    });

    test('no matching certificate', () {
      var claims = JsonWebTokenClaims.fromJson({});
      final builder = _getBuilder();
      builder.jsonContent = claims.toJson();
      builder.setProtectedHeader('kid', 'my-kid');
      final token = builder.build();

      when(() => client.read(Uri.parse(certificateUrl)))
          .thenAnswer((_) async => '{"missingKid": "cert"}');

      expect(
        verifyFirebaseToken(
          token.toCompactSerialization(),
          projectId: 'my-project-id',
        ),
        throwsA(
          predicate(
            (e) =>
                e is FirebaseVerifyException &&
                e.message == 'No certificate found matching with kid',
          ),
        ),
      );
    });

    test('expiry date', () {
      var claims = JsonWebTokenClaims.fromJson({});
      final builder = _getBuilder();
      builder.jsonContent = claims.toJson();
      builder.setProtectedHeader('kid', 'my-kid');
      final token = builder.build();

      when(() => client.read(Uri.parse(certificateUrl)))
          .thenAnswer((_) async => '{"$kid": "cert"}');

      expect(
        verifyFirebaseToken(
          token.toCompactSerialization(),
          projectId: 'my-project-id',
        ),
        throwsA(
          predicate(
            (e) =>
                e is FirebaseVerifyException &&
                e.message == 'Missing expiry date',
          ),
        ),
      );
    });

    test('expired token', () {
      final claims = JsonWebTokenClaims.fromJson({
        'exp': dateInThePast,
      });
      final builder = _getBuilder();
      builder.setProtectedHeader('kid', 'my-kid');
      builder.jsonContent = claims.toJson();
      final token = builder.build();

      when(() => client.read(Uri.parse(certificateUrl)))
          .thenAnswer((_) async => '{"$kid": "cert"}');

      expect(
        verifyFirebaseToken(
          token.toCompactSerialization(),
          projectId: 'my-project-id',
        ),
        throwsA(
          predicate(
            (e) => e is FirebaseVerifyException && e.message == 'Token expired',
          ),
        ),
      );
    });

    test('no auth time', () {
      final claims = JsonWebTokenClaims.fromJson({
        'exp': dateInTheFuture,
      });
      final builder = _getBuilder();
      builder.setProtectedHeader('kid', 'my-kid');
      builder.jsonContent = claims.toJson();
      final token = builder.build();

      when(() => client.read(Uri.parse(certificateUrl)))
          .thenAnswer((_) async => '{"$kid": "cert"}');

      expect(
        verifyFirebaseToken(
          token.toCompactSerialization(),
          projectId: 'my-project-id',
        ),
        throwsA(
          predicate(
            (e) =>
                e is FirebaseVerifyException &&
                e.message == 'Missing auth time',
          ),
        ),
      );
    });

    test('auth time in the future', () {
      final claims = JsonWebTokenClaims.fromJson({
        'exp': dateInTheFuture,
        'auth_time': dateInTheFuture,
      });
      final builder = _getBuilder();
      builder.setProtectedHeader('kid', 'my-kid');
      builder.jsonContent = claims.toJson();
      final token = builder.build();

      when(() => client.read(Uri.parse(certificateUrl)))
          .thenAnswer((_) async => '{"$kid": "cert"}');

      expect(
        verifyFirebaseToken(
          token.toCompactSerialization(),
          projectId: 'my-project-id',
        ),
        throwsA(
          predicate(
            (e) =>
                e is FirebaseVerifyException &&
                e.message == 'Authenticated in the future',
          ),
        ),
      );
    });

    test('no issue date', () {
      final claims = JsonWebTokenClaims.fromJson({
        'exp': dateInTheFuture,
        'auth_time': dateInThePast,
      });
      final builder = _getBuilder();
      builder.setProtectedHeader('kid', 'my-kid');
      builder.jsonContent = claims.toJson();
      final token = builder.build();

      when(() => client.read(Uri.parse(certificateUrl)))
          .thenAnswer((_) async => '{"$kid": "cert"}');

      expect(
        verifyFirebaseToken(
          token.toCompactSerialization(),
          projectId: 'my-project-id',
        ),
        throwsA(
          predicate(
            (e) =>
                e is FirebaseVerifyException &&
                e.message == 'Missing issued date',
          ),
        ),
      );
    });

    test('issue date in the future', () {
      final claims = JsonWebTokenClaims.fromJson({
        'exp': dateInTheFuture,
        'auth_time': dateInThePast,
        'iat': dateInTheFuture,
      });
      final builder = _getBuilder();
      builder.setProtectedHeader('kid', 'my-kid');
      builder.jsonContent = claims.toJson();
      final token = builder.build();

      when(() => client.read(Uri.parse(certificateUrl)))
          .thenAnswer((_) async => '{"$kid": "cert"}');

      expect(
        verifyFirebaseToken(
          token.toCompactSerialization(),
          projectId: 'my-project-id',
        ),
        throwsA(
          predicate(
            (e) =>
                e is FirebaseVerifyException &&
                e.message == 'Token issued in the future',
          ),
        ),
      );
    });

    test('wrong audience', () {
      final claims = JsonWebTokenClaims.fromJson({
        'exp': dateInTheFuture,
        'auth_time': dateInThePast,
        'iat': dateInThePast,
      });
      final builder = _getBuilder();
      builder.setProtectedHeader('kid', 'my-kid');
      builder.jsonContent = claims.toJson();
      final token = builder.build();

      when(() => client.read(Uri.parse(certificateUrl)))
          .thenAnswer((_) async => '{"$kid": "cert"}');

      expect(
        verifyFirebaseToken(
          token.toCompactSerialization(),
          projectId: 'my-project-id',
        ),
        throwsA(
          predicate(
            (e) =>
                e is FirebaseVerifyException && e.message == 'Wrong audience',
          ),
        ),
      );
    });

    test('wrong issuer', () {
      final claims = JsonWebTokenClaims.fromJson({
        'exp': dateInTheFuture,
        'auth_time': dateInThePast,
        'iat': dateInThePast,
        'aud': 'my-project-id',
      });
      final builder = _getBuilder();
      builder.setProtectedHeader('kid', 'my-kid');
      builder.jsonContent = claims.toJson();
      final token = builder.build();

      when(() => client.read(Uri.parse(certificateUrl)))
          .thenAnswer((_) async => '{"$kid": "cert"}');

      expect(
        verifyFirebaseToken(
          token.toCompactSerialization(),
          projectId: 'my-project-id',
        ),
        throwsA(
          predicate(
            (e) => e is FirebaseVerifyException && e.message == 'Wrong issuer',
          ),
        ),
      );
    });

    test('missing subject', () {
      final claims = JsonWebTokenClaims.fromJson({
        'exp': dateInTheFuture,
        'auth_time': dateInThePast,
        'iat': dateInThePast,
        'aud': 'my-project-id',
        'iss': 'https://securetoken.google.com/my-project-id',
      });
      final builder = _getBuilder();
      builder.setProtectedHeader('kid', 'my-kid');
      builder.jsonContent = claims.toJson();
      final token = builder.build();

      when(() => client.read(Uri.parse(certificateUrl)))
          .thenAnswer((_) async => '{"$kid": "cert"}');

      expect(
        verifyFirebaseToken(
          token.toCompactSerialization(),
          projectId: 'my-project-id',
        ),
        throwsA(
          predicate(
            (e) =>
                e is FirebaseVerifyException &&
                e.message == 'Subject data missing',
          ),
        ),
      );
    });

    test('wrong signature', () {
      final claims = JsonWebTokenClaims.fromJson({
        'exp': dateInTheFuture,
        'auth_time': dateInThePast,
        'iat': dateInThePast,
        'aud': 'my-project-id',
        'iss': 'https://securetoken.google.com/my-project-id',
        'sub': 'subject',
      });
      final builder = _getBuilder();
      builder.setProtectedHeader('kid', 'my-kid');
      builder.jsonContent = claims.toJson();
      final token = builder.build();

      when(() => client.read(Uri.parse(certificateUrl)))
          .thenAnswer((_) async => '{"$kid": "$_wrongPublicKey"}');

      expect(
        verifyFirebaseToken(
          token.toCompactSerialization(),
          projectId: 'my-project-id',
        ),
        throwsA(
          predicate(
            (e) =>
                e is FirebaseVerifyException &&
                e.message == 'The token signature is invalid',
          ),
        ),
      );
    });
  });

  group('Success:', () {
    test('gives JWT back', () async {
      final claims = JsonWebTokenClaims.fromJson({
        'exp': dateInTheFuture,
        'auth_time': dateInThePast,
        'iat': dateInThePast,
        'aud': 'my-project-id',
        'iss': 'https://securetoken.google.com/my-project-id',
        'sub': 'subject',
      });
      final builder = _getBuilder();
      builder.setProtectedHeader('kid', 'my-kid');
      builder.jsonContent = claims.toJson();
      final token = builder.build();

      when(() => client.read(Uri.parse(certificateUrl)))
          .thenAnswer((_) async => '{"$kid": "$_publicKey"}');

      expect(
        await verifyFirebaseToken(
          token.toCompactSerialization(),
          projectId: 'my-project-id',
        ),
        isA<FirebaseJWT>(),
      );
    });
  });
}

final _privateKey = '''-----BEGIN RSA PRIVATE KEY-----
'''
    '''
MIICXAIBAAKBgQCo/jMxcpmxnfU89ikhQ2d+k1BA8SKL1AAl3BwymFtILkBN/wG/
6PLnWw2rF5VmBEUPKEpf43cVaT45Fk/NRUTMoUXFLkJVsULJX80HQLu73XFKCU5S
47QqO8SB+4lJSd5ZtYciJaw/Lyfwa4ntv5lWxaYJdXjzSiHqntKIsG30FQIDAQAB
AoGAO+56pUypKQ6FzGrYR02qRH9l9MIPqFs0+jhHX8IcjUqpz39iVXb9vgLSpByn
BRj6jNeTGNKIhvVd9czt3DR2oy/4H7KKOFJ33eY3jpHLkBC60bmJa33A+hIXV5Uo
llDf4YgrotLA3QIR/f8uzDcB4ugZjuduISsgN12uPCKNgHkCQQDUCoZogr2j3yIK
5PgMnzlIT//i61paf4GACV6fEKVx5ThMi+RAiKWofuek1lANYk2T9i+CBw+cZFAs
4J7HQahnAkEAzAcElhm0mCuhL0PHo2D6X5yU2L5WDvuxnw48RUXTH73jy05vR625
hiSBrk6CVpKn5Esq2lelaSB25CuQ3E/iIwJAWIFoJtljhLIPSJLYApS3WTqjKTlp
hlqwWBwRFb3iAM9Xl4PQqyseUl1eHQyjb2K31OmuXMzLtFCesoyzWaJLQwJADWSQ
ioHZdvu2MvISEsl05f3TT37/CzC+ciBvGGUC/NxsLZZSe7QNr56J3LVOnPw3hSbi
Az8pnoMBCu1JLw0XXQJBAMrD8DctzTBmJK29W1o3pPoHVNhlpRZo8pdeLB18IpPR
/t/X8vkg0svCedhZjm2qxzY8Wa25l9SCF/r1yOSnqrA=
'''
    '''
-----END RSA PRIVATE KEY-----
''';

final _publicKey =
    '''-----BEGIN PUBLIC KEY-----\\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCo/jMxcpmxnfU89ikhQ2d+k1BA\\n8SKL1AAl3BwymFtILkBN/wG/6PLnWw2rF5VmBEUPKEpf43cVaT45Fk/NRUTMoUXF\\nLkJVsULJX80HQLu73XFKCU5S47QqO8SB+4lJSd5ZtYciJaw/Lyfwa4ntv5lWxaYJ\\ndXjzSiHqntKIsG30FQIDAQAB\\n-----END PUBLIC KEY-----\\n''';

final _wrongPublicKey =
    '''-----BEGIN PUBLIC KEY-----\\nMIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHkuFCqZjjIfbjyVJRGwBcGb3O9u\\nMbgloKQysuecRYzCOu39rQmdTK3FJ/GCBN1JHThvZP9UDBZdjHvR9IciKV5HpWbG\\nTqBFBdg7spI03+4U7fgvdtcOwcZVxKNpY7dQHz4L40rp5V4CviGGoU5NHB2VzSAc\\nL4/2X1R001eN/v5LAgMBAAE=\\n-----END PUBLIC KEY-----\\n''';
