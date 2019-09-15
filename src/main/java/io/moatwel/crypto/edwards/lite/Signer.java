package io.moatwel.crypto.edwards.lite;

import java.math.BigInteger;

public class Signer {

    private static final HashAlgorithm HASH_ALGORITHM = HashAlgorithm.SHA_512;
    private static final Curve25519 CURVE_25519 = Curve25519.getInstance();

    public Signature sign(PrivateKey privateKey, PublicKey publicKey, byte[] data) {
        byte[] h = Hashes.hash(HASH_ALGORITHM, privateKey.getRaw());

        // Step1
        byte[] first32 = ByteUtils.split(h, 32)[0];

        first32[0] &= 0xF8;
        first32[31] &= 0x7F;
        first32[31] |= 0x40;

        byte[] sSeed = ByteUtils.reverse(first32);
        BigInteger s = new BigInteger(sSeed);

        // Step2
        byte[] prefix = ByteUtils.split(h, 32)[1];

        byte[] rSeed = Hashes.hash(HASH_ALGORITHM, prefix, data);
        byte[] rSeedReversed = ByteUtils.reverse(rSeed);
        BigInteger r = new BigInteger(1, rSeedReversed);

        // Step3
        Group groupR = CURVE_25519.getBasePoint().scalarMultiply(r);
        byte[] rGroup = groupR.encode().getValue();

        // Step4
        byte[] kSeed = Hashes.hash(HASH_ALGORITHM, rGroup, publicKey.getRaw(), data);

        // Step5
        BigInteger k = new BigInteger(1, ByteUtils.reverse(kSeed));

        BigInteger groupS = k.mod(CURVE_25519.getPrimeL()).multiply(s).add(r).mod(CURVE_25519.getPrimeL());
        byte[] sGroup = new Field(groupS).encode().getValue();

        // Step6
        return new Signature(ByteUtils.paddingZeroOnTail(rGroup, 32),
                ByteUtils.paddingZeroOnTail(sGroup, 32));
    }
}
