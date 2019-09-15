package io.moatwel.crypto.edwards.lite;

import java.math.BigInteger;

public class EncodedGroup {
  private static final Curve25519 curve = Curve25519.getInstance();

  private byte[] value;

  EncodedGroup(byte[] value) {
    if (value.length != 32) {
      throw new IllegalArgumentException("EncodedPoint on ed25519 curve must have " +
          "32 byte length. The length of your EncodedPoint was " + value.length);
    }
    this.value = value;
  }

  public Group decode() throws DecodeException {
    // read bit for recovering x
    byte readTarget = value[value.length - 1];
    int x0 = ByteUtils.readBit(readTarget, 7);

    Field y = recoverY(this.value);

    Field x = recoverX(y, x0);

    return Group.fromAffine(x, y);
  }

  public byte[] getValue() {
    return value;
  }

  private Field recoverY(byte[] source) throws DecodeException {
    source[source.length - 1] &= 0x7F;
    BigInteger ySeed = new BigInteger(ByteUtils.reverse(source));
    if (ySeed.compareTo(curve.getPrimePowerP()) >= 1) {
      throw new DecodeException("EdDsa decoding failed. This point is not on the edwards Curve25519.");
    }
    return new Field(ySeed);
  }

  private Field recoverX(Field y, int xSource) throws DecodeException {
    Field u = y.multiply(y).subtract(Field.ONE).mod();
    Field v = (curve.getD().multiply(y).multiply(y).add(Field.ONE)).mod();
    Field xx = u.multiply(v.inverse()).mod();

    Field x = xx.powerMod(curve.getPrimePowerP().add(new BigInteger("3")).divide(new BigInteger("8")));

    if (x.multiply(x).subtract(xx).mod().getInteger().compareTo(BigInteger.ZERO) != 0) {
      if (x.multiply(x).add(xx).mod().getInteger().compareTo(BigInteger.ZERO) == 0) {
        x = x.multiply(new Field(
            BigInteger.ONE.shiftLeft(1).modPow(
                curve.getPrimePowerP().subtract(BigInteger.ONE).divide(BigInteger.ONE.shiftLeft(2)),
                curve.getPrimePowerP()))).mod();
      } else {
        throw new DecodeException("EdDsa decoding failed.");
      }
    }

    BigInteger result = x.getInteger().mod(BigInteger.ONE.shiftLeft(1));
    if (result.compareTo(BigInteger.valueOf((long) xSource)) != 0) {
      x = new Field(curve.getPrimePowerP().subtract(x.getInteger()).mod(curve.getPrimePowerP()));
    }

    return x;
  }
}
