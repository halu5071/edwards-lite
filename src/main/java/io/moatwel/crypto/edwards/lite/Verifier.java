package io.moatwel.crypto.edwards.lite;

public class Verifier {

  private static final HashAlgorithm HASH_ALGORITHM = HashAlgorithm.SHA_512;
  private static final Curve25519 CURVE_25519 = Curve25519.getInstance();

  public boolean verify(Signature signature, PublicKey publicKey, byte[] data) {
    try {
      byte[] rSeed = signature.getR();
      EncodedGroup encodedR = new EncodedGroup(rSeed);
      Group r = encodedR.decode();

      EncodedGroup encodedPublicKey = new EncodedGroup(publicKey.getRaw());
      Group a = encodedPublicKey.decode();

      EncodedField encodedS = new EncodedField(signature.getS());
      Field s = encodedS.decode();

      byte[] kSeed = Hashes.hash(HASH_ALGORITHM, r.encode().getValue(), publicKey.getRaw(), data);
      Field k = new EncodedField(kSeed).decode();

      Group checkPoint = r.add(a.scalarMultiply(k.getInteger()));

      Group target = CURVE_25519.getBasePoint().scalarMultiply(s.getInteger());

      return checkPoint.isEqual(target);
    } catch (DecodeException e) {
      return false;
    }
  }
}
