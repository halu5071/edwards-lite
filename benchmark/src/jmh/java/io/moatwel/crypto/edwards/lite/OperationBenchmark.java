package io.moatwel.crypto.edwards.lite;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class OperationBenchmark {

  private PrivateKey privateKey = PrivateKey.random();
  private KeyGenerator keyGenerator = new KeyGenerator();
  private PublicKey publicKey = keyGenerator.generatePublicKey(privateKey);
  private Signer signer = new Signer();
  private Verifier verifier = new Verifier();
  private Signature signature = signer.sign(privateKey, publicKey, new byte[0]);

  @Benchmark
  public void publicKey() {
    keyGenerator.generatePublicKey(privateKey);
  }

  @Benchmark
  public void sign() {
    signer.sign(privateKey, publicKey, new byte[0]);
  }

  @Benchmark
  public void verify() {
    verifier.verify(signature, publicKey, new byte[0]);
  }
}
