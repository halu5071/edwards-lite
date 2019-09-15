package io.moatwel.crypto.edwards.lite;

import java.math.BigInteger;

public class Group {
  private static final Curve25519 curve = Curve25519.getInstance();
  private static final Field DEFAULT_Z = new Field(BigInteger.ONE);
  static final Group O = new Group(Field.ZERO, Field.ONE, DEFAULT_Z, Field.ZERO);

  private Field x;
  private Field y;
  private Field z;
  private Field t;

  public static Group fromAffine(Field x, Field y) {
    return new Group(
        x.multiply(DEFAULT_Z).mod(),
        y.multiply(DEFAULT_Z).mod(),
        DEFAULT_Z,
        x.multiply(y).multiply(DEFAULT_Z).mod()
    );
  }

  Group(Field x, Field y, Field z, Field t) {
    this.x = x;
    this.y = y;
    this.z = z;
    this.t = t;
  }

  public Group add(Group group) {
    Field x1 = this.x;
    Field y1 = this.y;
    Field z1 = this.z;
    Field t1 = this.t;
    Field x2 = group.getX();
    Field y2 = group.getY();
    Field z2 = group.getZ();
    Field t2 = group.getT();

    Field d = new Field(curve.getD().getInteger());
    Field coord2 = new Field(BigInteger.ONE.shiftLeft(1));

    Field A = y1.subtract(x1).multiply(y2.subtract(x2)).mod();
    Field B = y1.add(x1).multiply(y2.add(x2)).mod();
    Field C = t1.multiply(coord2).multiply(d).multiply(t2).mod();
    Field D = z1.multiply(coord2).multiply(z2).mod();
    Field E = B.subtract(A).mod();
    Field F = D.subtract(C).mod();
    Field G = D.add(C).mod();
    Field H = B.add(A).mod();

    Field x3 = E.multiply(F).mod();
    Field y3 = G.multiply(H).mod();
    Field z3 = F.multiply(G).mod();
    Field t3 = E.multiply(H).mod();

    return new Group(x3, y3, z3, t3);
  }

  public Group scalarMultiply(BigInteger integer) {
    if (integer.equals(BigInteger.ZERO)) {
      return O;
    }

    Group result = this;
    int[] binArray = ArrayUtils.toBinaryArray(integer);

    for (int i = 1; i < binArray.length; i++) {
      result = result.add(result);
      if (binArray[i] == 1) {
        result = result.add(this);
      }
    }
    return result;
  }

  public Group negateY() {
    return new Group(x, y.negate(), z, t);
  }

  public final EncodedGroup encode() {
    byte[] reversedY = ByteUtils.reverse(ArrayUtils.toByteArray(getAffineY().getInteger(), 32));
    reversedY = ByteUtils.paddingZeroOnTail(reversedY, 32);
    byte[] byteX = ArrayUtils.toByteArray(getAffineX().getInteger(), 32);
    int lengthX = byteX.length;
    int lengthY = reversedY.length;
    int writeBit = byteX[lengthX - 1] & 0b00000001;

    if (writeBit == 1) {
      reversedY[lengthY - 1] |= 1 << 7;
    } else {
      writeBit = ~(1 << 7);
      reversedY[lengthY - 1] &= writeBit;
    }

    return new EncodedGroup(reversedY);
  }

  public boolean isEqual(Group group) {
    return getAffineX().isEqual(group.getAffineX()) && getAffineY().isEqual(group.getAffineY());
  }

  public Field getAffineX() {
    return x.multiply(z.inverse()).mod();
  }

  public Field getAffineY() {
    return y.multiply(z.inverse()).mod();
  }

  public Field getX() {
    return x;
  }

  public Field getY() {
    return y;
  }

  public Field getZ() {
    return z;
  }

  public Field getT() {
    return t;
  }
}
