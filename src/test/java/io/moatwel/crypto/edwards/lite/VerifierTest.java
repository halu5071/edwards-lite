package io.moatwel.crypto.edwards.lite;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class VerifierTest {

    private Verifier verifier = new Verifier();

    @Test
    public void test_verify_1() {
        // from SignerTest.test_Signature_1
        PublicKey publicKey = PublicKey.fromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

        // Signature of data new byte[0]
        Signature signature = new Signature(
                HexEncoder.getBytes(
                        "e5564300c360ac729086e2cc806e828a" +
                        "84877f1eb8e5d974d873e06522490155"),
                HexEncoder.getBytes(
                        "5fb8821590a33bacc61e39701cf9b46b" +
                        "d25bf5f0595bbe24655141438e7a100b"));

        boolean isVerified = verifier.verify(signature, publicKey, new byte[0]);

        assertThat(isVerified, is(true));
    }

    @Test
    public void test_verify_1_different_data_bytes() {
        // from SignerTest.test_Signature_1
        PublicKey publicKey = PublicKey.fromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

        // Signature of data new byte[0]
        Signature signature = new Signature(
                HexEncoder.getBytes(
                        "e5564300c360ac729086e2cc806e828a" +
                                "84877f1eb8e5d974d873e06522490155"),
                HexEncoder.getBytes(
                        "5fb8821590a33bacc61e39701cf9b46b" +
                                "d25bf5f0595bbe24655141438e7a100b"));

        boolean isVerified = verifier.verify(signature, publicKey, new byte[1]);

        assertThat(isVerified, is(false));
    }

    @Test
    public void test_verify_1_different_public_key() {
        // from SignerTest.test_Signature_1
        // different public key
        PublicKey publicKey = PublicKey.fromHexString("a75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

        // Signature of data new byte[0]
        Signature signature = new Signature(
                HexEncoder.getBytes(
                        "e5564300c360ac729086e2cc806e828a" +
                                "84877f1eb8e5d974d873e06522490155"),
                HexEncoder.getBytes(
                        "5fb8821590a33bacc61e39701cf9b46b" +
                                "d25bf5f0595bbe24655141438e7a100b"));

        boolean isVerified = verifier.verify(signature, publicKey, new byte[0]);

        assertThat(isVerified, is(false));
    }

    @Test
    public void test_verify_1_different_Signature_1() {
        // from SignerTest.test_Signature_1
        PublicKey publicKey = PublicKey.fromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

        // Signature of data new byte[0]
        // different Signature R
        Signature signature = new Signature(
                HexEncoder.getBytes(
                        "a5564300c360ac729086e2cc806e828a" +
                                "84877f1eb8e5d974d873e06522490155"),
                HexEncoder.getBytes(
                        "5fb8821590a33bacc61e39701cf9b46b" +
                                "d25bf5f0595bbe24655141438e7a100b"));

        boolean isVerified = verifier.verify(signature, publicKey, new byte[0]);

        assertThat(isVerified, is(false));
    }

    @Test
    public void test_verify_1_different_Signature_2() {
        // from SignerTest.test_Signature_1
        PublicKey publicKey = PublicKey.fromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

        // Signature of data new byte[0]
        // different Signature R
        Signature signature = new Signature(
                HexEncoder.getBytes(
                        "e5564300c360ac729086e2cc806e828a" +
                                "84877f1eb8e5d974d873e06522490155"),
                HexEncoder.getBytes(
                        "5fb8821590a33bacc61e39701cf9b46b" +
                                "d25bf5f0595bbe24655141438e7a100c"));

        boolean isVerified = verifier.verify(signature, publicKey, new byte[0]);

        assertThat(isVerified, is(false));
    }
}
