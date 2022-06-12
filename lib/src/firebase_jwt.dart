/// A model to store the decoded JWT data.
class FirebaseJWT {
  final Map<String, dynamic> headers;
  final Map<String, dynamic> payload;
  FirebaseJWT({required this.headers, required this.payload});
}
