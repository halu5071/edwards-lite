package io.moatwel.crypto.edwards.lite;

import java.math.BigInteger;

public class Signature {

    private byte[] r;
    private byte[] s;

    Signature(BigInteger r, BigInteger s) {
        this(ArrayUtils.toByteArray(r, 32), ArrayUtils.toByteArray(s, 32));
    }

    Signature(byte[] byteR, byte[] byteS) {
        if (byteR.length != 32 || byteS.length != 32) {
            throw new IllegalArgumentException("Signature on Curve25519 must have 32 byte length.");
        }
        this.r = byteR;
        this.s = byteS;
    }

    public byte[] getR() {
        return r;
    }

    public byte[] getS() {
        return s;
    }

    public byte[] getSignature() {
        return ByteUtils.join(r, s);
    }
}
