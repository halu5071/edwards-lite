package io.moatwel.crypto.edwards.lite;

import java.math.BigInteger;

public class Group {
    static final Group O = new Group(Field.ZERO, Field.ONE);

    private static final Field Z1 = new Field(BigInteger.ONE);
    private static final Field Z2 = new Field(BigInteger.ONE);
    private static final Curve25519 curve = Curve25519.getInstance();

    private Field x;
    private Field y;

    Group(Field x, Field y) {
        this.x = x;
        this.y = y;
    }

    public Group add(Group group) {
        Field x1 = this.x.multiply(Z1).mod();
        Field y1 = this.y.multiply(Z1).mod();
        Field x2 = group.getX().multiply(Z2).mod();
        Field y2 = group.getY().multiply(Z2).mod();

        Field t1 = x1.multiply(y1).multiply(Z1).mod();
        Field t2 = x2.multiply(y2).multiply(Z2).mod();

        Field d = new Field(curve.getD().getInteger());
        Field coord2 = new Field(BigInteger.ONE.shiftLeft(1));

        Field A = y1.subtract(x1).multiply(y2.subtract(x2)).mod();
        Field B = y1.add(x1).multiply(y2.add(x2)).mod();
        Field C = t1.multiply(coord2).multiply(d).multiply(t2).mod();
        Field D = Z1.multiply(coord2).multiply(Z2).mod();
        Field E = B.subtract(A);
        Field F = D.subtract(C);
        Field G = D.add(C);
        Field H = B.add(A);

        Field Z3 = F.multiply(G).mod();

        Field x3 = E.multiply(F).multiply(Z3.inverse()).mod();
        Field y3 = G.multiply(H).multiply(Z3.inverse()).mod();

        return new Group(x3, y3);
    }

    public Group scalarMultiply(BigInteger integer) {
        if (integer.equals(BigInteger.ZERO)) {
            return Group.O;
        }

        Group[] qs = new Group[]{O, O};
        Group[] rs = new Group[]{this, this, negateY()};

        int[] signedBin = ArrayUtils.toMutualOppositeForm(integer);

        for (int aSignedBin : signedBin) {
            qs[0] = qs[0].add(qs[0]);
            qs[1] = (qs[0].add(rs[1 - aSignedBin])).negate();
            qs[0] = qs[(aSignedBin ^ (aSignedBin >> 31)) - (aSignedBin >> 31)];
        }
        return qs[0];
    }

    public Group negateY() {
        return new Group(x, y.negate());
    }

    public final EncodedGroup encode() {
        byte[] reversedY = ByteUtils.reverse(ArrayUtils.toByteArray(y.getInteger(), 32));
        reversedY = ByteUtils.paddingZeroOnTail(reversedY, 32);
        byte[] byteX = ArrayUtils.toByteArray(x.getInteger(), 32);
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
        return x.isEqual(group.getX()) && y.isEqual(group.getY());
    }

    public Field getX() {
        return x;
    }

    public Field getY() {
        return y;
    }

    private Group negate() {
        return new Group(x.negate(), y.negate());
    }
}
