package io.moatwel.crypto.edwards.lite;

import org.junit.Test;

import java.math.BigInteger;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

public class FieldTest {
    @Test
    public void success_GenerateField_byte_array_length_32() {
        BigInteger integer = new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202");
        assertThat(integer.toByteArray().length, is(32));
        Field field = new Field(integer);

        assertNotNull(field);
        assertThat(field.getInteger().toByteArray().length, is(32));
    }

    @Test
    public void success_AddField() {
        Field field1 = new Field(new BigInteger("1"));
        Field field2 = new Field(new BigInteger("2"));

        Field result = field1.add(field2);

        assertEquals(result.getInteger(), new BigInteger("3"));
    }

    @Test
    public void success_DivideField() {
        Field field1 = new Field(new BigInteger("1000"));
        Field field2 = new Field(new BigInteger("2"));

        Field result = field1.divide(field2);

        assertEquals(result.getInteger(), new BigInteger("500"));
    }

    @Test
    public void success_MultiplyField() {
        Field field1 = new Field(new BigInteger("1000"));
        Field field2 = new Field(new BigInteger("2"));

        Field result = field1.multiply(field2);

        assertEquals(result.getInteger(), new BigInteger("2000"));
    }

    @Test
    public void success_InverseField() {
        Field field1 = new Field(new BigInteger("100"));
        Field field2 = new Field(new BigInteger("101241240"));

        Field result1 = field1.inverse();
        Field result2 = field2.inverse();

        assertThat(result1.getInteger(), is(new BigInteger("29526982755515629833010601177215416502583846089738343830061683922017848058174")));
        assertThat(result2.getInteger(), is(new BigInteger("38867791596533294917564303539771571723867178851912571219685671691706937241210")));
    }

    @Test
    public void success_SomeOperation() {
        Field field1 = new Field(new BigInteger("1000"));
        Field field2 = new Field(new BigInteger("2"));
        Field field3 = new Field(new BigInteger("4"));
        Field field4 = new Field(new BigInteger("14"));
        Field field5 = new Field(new BigInteger("-1"));

        Field result = field1.add(field3).multiply(field2).mod();
        Field result2 = field2.multiply(field3).add(field1).mod();
        Field result3 = field2.multiply(field1).subtract(field4).mod();
        Field result4 = field3.add(field4).add(field1).multiply(field2).mod();
        Field result5 = field2.multiply(field1).subtract(field2.multiply(field4)).mod();
        Field result6 = field5.multiply(field1);

        assertThat(result.getInteger(), is(new BigInteger("2008")));
        assertThat(result2.getInteger(), is(new BigInteger("1008")));
        assertThat(result3.getInteger(), is(new BigInteger("1986")));
        assertThat(result4.getInteger(), is(new BigInteger("2036")));
        assertThat(result5.getInteger(), is(new BigInteger("1972")));

        assertThat(field5.getInteger(), is(BigInteger.ONE.negate()));
        assertThat(result6.getInteger(), is(new BigInteger("-1000")));
    }

    @Test
    public void success_IsEqual_true_1() {
        Field field1 = new Field(new BigInteger("29526982755515629833010601177215416502583846089738343830061683922017848058174"));
        Field field2 = new Field(new BigInteger("29526982755515629833010601177215416502583846089738343830061683922017848058174"));

        assertThat(field1.isEqual(field2), is(true));
    }

    @Test
    public void success_IsEqual_false_1() {
        Field field1 = new Field(new BigInteger("29526982755515629833010601177215416502583846089738343830061683922017848058174"));
        Field field2 = new Field(new BigInteger("84412282755515629833010601177215416502583846089738343830061683922017848058174"));

        assertThat(field1.isEqual(field2), is(false));
    }

    @Test
    public void success_Encode_1() {
        Field field1 = new Field(new BigInteger("1073164242609237669094038971348660945523306704071742924708751717996060223455"));
        EncodedField encoded = field1.encode();

        assertThat(HexEncoder.getString(encoded.getValue()), is("df2780568c569c6713ed48bc7d96e04a93fdda45237bfc34afe40518b2635f02"));
    }

    @Test
    public void success_Encode_2() {
        Field field1 = new Field(new BigInteger("4016116405453202388474865418908325977025123430952466464539276325205466974574"));
        EncodedField encoded = field1.encode();

        assertThat(HexEncoder.getString(encoded.getValue()), is("6e89e4b5973ab73a1538714746c77fd09f33aeeebdf11daffd94d6ba940ae108"));
    }

    @Test
    public void success_Encode_3() {
        Field field1 = new Field(new BigInteger("5635526907038231869349643959556202269054548263441123979990494297630113764337"));
        EncodedField encoded = field1.encode();

        assertThat(HexEncoder.getString(encoded.getValue()), is("f193d7d58eb5ba3482c54b4dad4f9685726b2957cdf363fd4c6ed5a85e98750c"));
    }

    @Test
    public void success_Encode_4() {
        Field field1 = new Field(new BigInteger("466061824698566712370651010976869652622695944005000025458774533499639142642"));
        EncodedField encoded = field1.encode();

        assertThat(HexEncoder.getString(encoded.getValue()), is("f29829ffdb3b229fd05dc7f83c1de7ab041cbbeb4156d7442f3e23de19c80701"));
    }

    @Test
    public void success_Encode_5() {
        Field field1 = new Field(new BigInteger("690082385501664621091624779109445751481919948714921317484605800924977635702"));
        EncodedField encoded = field1.encode();

        assertThat(HexEncoder.getString(encoded.getValue()), is("762115b81aae8ab7a87e5d205ee64173ffc2666721b9bed118c4af49a2928601"));
    }

    @Test
    public void success_Negate_1() {
        // Base point
        Field field1 = new Field(new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202"));
        Field field2 = new Field(new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960"));

        Field field3 = new Field(new BigInteger("29526982755515629833010601177215416502583846089738343830061683922017848058174"));
        Field field4 = new Field(new BigInteger("38867791596533294917564303539771571723867178851912571219685671691706937241210"));

        Field negated1 = field1.negate();
        Field negated2 = field2.negate();
        Field negated3 = field3.negate();
        Field negated4 = field4.negate();

        assertThat(negated1.getInteger(), is(new BigInteger("42783823269122696939284341094755422415180979639778424813682678720006717057747")));
        assertThat(negated2.getInteger(), is(new BigInteger("11579208923731619542357098500868790785326998466564056403945758400791312963989")));
        assertThat(negated3.getInteger(), is(new BigInteger("28369061863142467878774891327128537424051146243081938189667108081938716761775")));
        assertThat(negated4.getInteger(), is(new BigInteger("19028253022124802794221188964572382202767813480907710800043120312249627578739")));
    }
}
