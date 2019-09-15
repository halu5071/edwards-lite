package io.moatwel.crypto.edwards.lite;

import java.math.BigInteger;

public class Curve25519 {
  private Curve25519() {
  }

  public static Curve25519 getInstance() {
    return CurveHolder.INSTANCE;
  }

  public final int getPublicKeyByteLength() {
    return 32;
  }

  public final Group getBasePoint() {
    Field x = new Field(new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202"));
    Field y = new Field(new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960"));
    return new Group(x, y);
  }

  public final BigInteger getPrimeL() {
    return BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
  }

  public final BigInteger getPrimePowerP() {
    return BigInteger.ONE.shiftLeft(255).subtract(new BigInteger("19"));
  }

  public final Field getD() {
    BigInteger d = new BigInteger("-121665")
        .multiply(new BigInteger("121666").modInverse(getPrimePowerP()))
        .mod(getPrimePowerP());
    return new Field(d);
  }

  public final BigInteger getA() {
    return new BigInteger("-1");
  }

  private static class CurveHolder {
    private static final Curve25519 INSTANCE = new Curve25519();
  }
}
