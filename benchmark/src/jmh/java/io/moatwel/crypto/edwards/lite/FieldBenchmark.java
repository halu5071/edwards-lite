package io.moatwel.crypto.edwards.lite;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;

import java.math.BigInteger;

@State(Scope.Benchmark)
public class FieldBenchmark {
  private Field fieldX = new Field(new BigInteger("20266806181347897178517736945403300566236311925948585575972021784256181966831"));
  private Field fieldY = new Field(new BigInteger("20852410506957026626210500909507772892959249564214740554270305643381675686982"));

  @Benchmark
  public void add() {
    fieldX.add(fieldY);
  }

  @Benchmark
  public void subtract() {
    fieldY.subtract(fieldX);
  }

  @Benchmark
  public void multiply() {
    fieldX.multiply(fieldY);
  }

  @Benchmark
  public void inverse() {
    fieldX.inverse();
  }
}
