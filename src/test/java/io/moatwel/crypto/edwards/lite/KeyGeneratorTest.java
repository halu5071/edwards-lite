package io.moatwel.crypto.edwards.lite;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class KeyGeneratorTest {

    private KeyGenerator keyGenerator = new KeyGenerator();

    @Test
    public void generate() {
        PrivateKey privateKey = PrivateKey.fromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");

        PublicKey publicKey = keyGenerator.generatePublicKey(privateKey);

        assertThat(publicKey.getHexString(), is("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
    }
}
