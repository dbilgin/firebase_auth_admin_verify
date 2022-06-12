# Firebase Auth Admin Verify

[![Pub Version](https://img.shields.io/pub/v/firebase_auth_admin_verify?color=blueviolet)](https://pub.dev/packages/firebase_auth_admin_verify)

A JWT verification tool specifically for Firebase Auth JWTs.

## Installation

Add `firebase_auth_admin_verify` as a [dependency in your pubspec.yaml file](https://flutter.io/platform-plugins/).

<h1>Usage</h1>

```dart
import 'package:firebase_auth_admin_verify/firebase_auth_admin_verify.dart';

try {
  // **With project id:**
  final jwt1 = await verifyFirebaseToken('ey...', projectId: 'my-project-id');

  // **With service file at the root:**
  final jwt2 = await verifyFirebaseToken('ey...');

  // **With service account file:**
  final jwt3 = await verifyFirebaseToken('ey...', serviceFilePath: 'path/to/service-account.json');
} catch (e) {

}
```

For more detailed examples you can check out the [example project](https://github.com/dbilgin/firebase_auth_admin_verify/tree/master/example).
