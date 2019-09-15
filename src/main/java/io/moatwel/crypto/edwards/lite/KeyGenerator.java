package io.moatwel.crypto.edwards.lite;

import java.math.BigInteger;

public class KeyGenerator {

    private static final HashAlgorithm HASH_ALGORITHM = HashAlgorithm.SHA_512;
    private static final Curve25519 CURVE_25519 = Curve25519.getInstance();

    public PublicKey generatePublicKey(PrivateKey privateKey) {
        byte[] hashResult = Hashes.hash(HASH_ALGORITHM, privateKey.getRaw());
        byte[] first32 = ByteUtils.split(hashResult, 32)[0];

        first32[0] &= 0xF8;
        first32[31] &= 0x7F;
        first32[31] |= 0x40;

        byte[] a = ByteUtils.reverse(first32);

        BigInteger s = new BigInteger(a);

        Group group = CURVE_25519.getBasePoint().scalarMultiply(s);
        byte[] seed = group.encode().getValue();

        return new PublicKey(seed);
    }
}
