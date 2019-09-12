package io.moatwel.crypto.edwards.lite;

import java.math.BigInteger;

public class Field {
    private static final Curve25519 curve = Curve25519.getInstance();

    public static final Field ZERO = new Field(BigInteger.ZERO);
    public static final Field ONE = new Field(BigInteger.ONE);

    private BigInteger value;

    Field(BigInteger integer) {
        this.value = integer;
    }

    public final Field add(Field val) {
        BigInteger integer = val.getInteger();
        return new Field(value.add(integer));
    }

    public Field divide(Field val) {
        return new Field(value.divide(val.getInteger()));
    }

    public Field multiply(Field val) {
        BigInteger integer = val.getInteger();
        return new Field(value.multiply(integer));
    }

    public Field subtract(Field val) {
        BigInteger integer = val.getInteger();
        return new Field(value.subtract(integer));
    }

    public Field mod() {
        return new Field(getInteger().mod(curve.getPrimePowerP()));
    }

    public Field inverse() {
        return new Field(getInteger().modInverse(curve.getPrimePowerP()));
    }

    public Field powerMod(BigInteger exponent) {
        return new Field(value.modPow(exponent, curve.getPrimePowerP()));
    }

    public Field negate() {
        return new Field(value.negate()).mod();
    }

    public BigInteger getInteger() {
        return value;
    }

    public EncodedField encode() {
        byte[] seed = ByteUtils.reverse(ArrayUtils.toByteArray(value, 32));
        return new EncodedField(seed);
    }

    public boolean isEqual(Field field) {
        return value.compareTo(field.value) == 0;
    }
}
