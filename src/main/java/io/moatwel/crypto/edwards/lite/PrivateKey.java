package io.moatwel.crypto.edwards.lite;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class PrivateKey {
    private byte[] value;

    PrivateKey(byte[] value) {
        if (value.length != 32) {
            throw new IllegalArgumentException("PrivateKey on ed25519 curve must have 32 byte length");
        }
        this.value = value;
    }

    public static PrivateKey fromHexString(String hexString) {
        return new PrivateKey(HexEncoder.getBytes(hexString));
    }

    public static PrivateKey fromBytes(byte[] bytes) {
        return new PrivateKey(bytes);
    }

    public static PrivateKey random() {
        byte[] seed = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(seed);
        return new PrivateKey(seed);
    }

    public byte[] getRaw() {
        return value;
    }

    public BigInteger getInteger() {
        return new BigInteger(1, value);
    }

    public String getHexString() {
        return HexEncoder.getString(this.value);
    }

    public BigInteger getScalarSeed(HashAlgorithm hashAlgorithm) {
        byte[] hashResult = Hashes.hash(hashAlgorithm, value);
        byte[] first32 = ByteUtils.split(hashResult, 32)[0];

        first32[0] &= 0xF8;
        first32[31] &= 0x7F;
        first32[31] |= 0x40;

        byte[] a = ByteUtils.reverse(first32);
        return new BigInteger(a);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(this.value);
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof PrivateKey)) {
            return false;
        }
        final PrivateKey privateKey = ((PrivateKey) obj);
        return this.value.equals(privateKey.value);
    }
}
