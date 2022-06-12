class FirebaseVerifyException implements Exception {
  final String message;
  FirebaseVerifyException(this.message);

  @override
  String toString() {
    return 'FirebaseVerifyException: $message';
  }
}
