package io.moatwel.crypto.edwards.lite;

import org.junit.Test;

import java.math.BigInteger;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class EncodedGroupTest {
  @Test
  public void success_DecodeGroup_1() throws DecodeException {
    EncodedGroup encodedGroup = new EncodedGroup(HexEncoder.getBytes("467c72ee4596e75c4ccda69acd1f528df3a9e6d787c2fb992f313417cd0b1aae"));

    Group group = encodedGroup.decode();

    assertThat(group.getX().getInteger(), is(new BigInteger("20266806181347897178517736945403300566236311925948585575972021784256181966831")));
    assertThat(group.getY().getInteger(), is(new BigInteger("20852410506957026626210500909507772892959249564214740554270305643381675686982")));
  }

  @Test
  public void success_DecodeGroup_2() throws DecodeException {
    EncodedGroup encodedGroup = new EncodedGroup(HexEncoder.getBytes("a631abbdf283aa8c79f23967935399e71d720eec6c4e90ccd57ae562eeb8498f"));

    Group group = encodedGroup.decode();

    assertThat(group.getX().getInteger(), is(new BigInteger("11675954373387894284288004270057647646117187555908725144338394611307421402153")));
    assertThat(group.getY().getInteger(), is(new BigInteger("6914948912687941235153802070429816612825513145320139793692760076939195789734")));
  }

  @Test
  public void success_DecodeGroup_3() throws DecodeException {
    EncodedGroup encodedGroup = new EncodedGroup(HexEncoder.getBytes("deffe1a9ccc8ba06b10782013fbaa8154f4350e04e862151faac0cde3523278a"));

    Group group = encodedGroup.decode();

    assertThat(group.getX().getInteger(), is(new BigInteger("55307901837819056100203421472284281626339181044463972151446027320031681414103")));
    assertThat(group.getY().getInteger(), is(new BigInteger("4592278534742875130003490239944802183338230954052483234431143871319686381534")));
  }

  @Test
  public void success_DecodeGroup_4() throws DecodeException {
    EncodedGroup encodedGroup = new EncodedGroup(HexEncoder.getBytes("354028754b43b4a27535a82375a7d4edefa90ced814e8a67ef543eb7911fb0f1"));

    Group group = encodedGroup.decode();

    assertThat(group.getX().getInteger(), is(new BigInteger("34533599460759434840195068027488100886792431177105624727278431380599494051297")));
    assertThat(group.getY().getInteger(), is(new BigInteger("51422534855936905954058747336281739654670737325900075107235061596710295322677")));
  }

  @Test
  public void success_DecodeGroup_5() throws DecodeException {
    EncodedGroup encodedGroup = new EncodedGroup(HexEncoder.getBytes("840ce11e453af4c2e48fbec448b7de3957e167c16f8e72051c535dd75281e574"));

    Group group = encodedGroup.decode();

    assertThat(group.getX().getInteger(), is(new BigInteger("53796438671359824102085853653404738634771041230653645888564199631429825277660")));
    assertThat(group.getY().getInteger(), is(new BigInteger("52873790972168047993308827189322012202737756658766965387349495052412272053380")));
  }

  @Test
  public void success_DecodeGroup_6() throws DecodeException {
    EncodedGroup encodedGroup = new EncodedGroup(HexEncoder.getBytes("0b67a11b2564accd38d9b963ac22eb64ed2ec9c17de25f7fe3209afc21886702"));

    Group group = encodedGroup.decode();

    assertThat(group.getX().getInteger(), is(new BigInteger("31621228259983782766387151846173419701451207683454700670358544852161525834558")));
    assertThat(group.getY().getInteger(), is(new BigInteger("1087550498622212171315934886475455672530696511327350732598338573849547859723")));
  }

  @Test
  public void success_DecodeGroup_7() throws DecodeException {
    EncodedGroup encodedGroup = new EncodedGroup(HexEncoder.getBytes("60d01f4c733a4e4f6890e67c8c62693e5c1dc7cadd68be5dfab0fe9f41011948"));

    Group group = encodedGroup.decode();

    assertThat(group.getX().getInteger(), is(new BigInteger("24714885350915573524959492804958774885039633758708007137167239543662320763472")));
    assertThat(group.getY().getInteger(), is(new BigInteger("32610704945606948033834599741453719010166132071117736619400925734673110257760")));
  }

  @Test
  public void success_DecodeGroup_8() throws DecodeException {
    EncodedGroup encodedGroup = new EncodedGroup(HexEncoder.getBytes("24a2101437ae0680dc1425e0fc43ad7bbcfeec01ec4831b3907290d5443e5296"));

    Group group = encodedGroup.decode();

    assertThat(group.getX().getInteger(), is(new BigInteger("15859889424997121447678417203126552703333111509882764573373873495686990760265")));
    assertThat(group.getY().getInteger(), is(new BigInteger("10096193892184502829137016296170451381135740053910753749871387609999636210212")));
  }

  @Test
  public void success_DecodeGroup_9() throws DecodeException {
    EncodedGroup encodedGroup = new EncodedGroup(HexEncoder.getBytes("467c72ee4596e75c4ccda69acd1f528df3a9e6d787c2fb992f313417cd0b1aae"));

    Group group = encodedGroup.decode();

    assertThat(group.getX().getInteger(), is(new BigInteger("20266806181347897178517736945403300566236311925948585575972021784256181966831")));
    assertThat(group.getY().getInteger(), is(new BigInteger("20852410506957026626210500909507772892959249564214740554270305643381675686982")));
  }

  @Test
  public void success_DecodeGroup_10() throws DecodeException {
    EncodedGroup encodedGroup = new EncodedGroup(HexEncoder.getBytes("b195102f70426e51c8e8ed0e31e74447e0b461a85e1ec14397bb88acbcfc15c8"));

    Group group = encodedGroup.decode();

    assertThat(group.getX().getInteger(), is(new BigInteger("51129866767904606553230589361247885151272909473749371102570783512913896553871")));
    assertThat(group.getY().getInteger(), is(new BigInteger("32605373213074853449054031639075642571848374710300664057820958199552138057137")));
  }

  @Test
  public void success_DecodeGroup_11() throws DecodeException {
    EncodedGroup encodedGroup = new EncodedGroup(HexEncoder.getBytes("0a7839c8658c2186c5650644ee832c092cb46bff7c6a777621567dd5c9e8c8c3"));

    Group group = encodedGroup.decode();

    assertThat(group.getX().getInteger(), is(new BigInteger("13267040035417295396187264812269447027004279287377164120608901297558640265393")));
    assertThat(group.getY().getInteger(), is(new BigInteger("30659936914619338944546583179452063721257503761316379129960678675145268230154")));
  }

  @Test
  public void success_DecodeGroup_12() throws DecodeException {
    EncodedGroup encodedGroup = new EncodedGroup(HexEncoder.getBytes("17ccd9301c1504aa65aed4872634d7317707fd8e95bbc3b4c4e732be73baf074"));

    Group group = encodedGroup.decode();

    assertThat(group.getX().getInteger(), is(new BigInteger("50505920206304101148506670769962044834562415690945180860800334635063441812972")));
    assertThat(group.getY().getInteger(), is(new BigInteger("52893620576450359719018512374896078131701031161676122303582965125535080500247")));
  }

  @Test
  public void success_DecodeGroup_13() throws DecodeException {
    EncodedGroup encodedGroup = new EncodedGroup(HexEncoder.getBytes("1782e3085548baead1ac7ab9befa1259f892e59102ac7022506e6de0940c9fed"));

    Group group = encodedGroup.decode();

    assertThat(group.getX().getInteger(), is(new BigInteger("5288904915125359943317363554591172762473106809525857286939154287576903061215")));
    assertThat(group.getY().getInteger(), is(new BigInteger("49583116013539038265297505995597360672194268243619584093840920874690478834199")));
  }

  @Test
  public void success_DecodeGroup_14() throws DecodeException {
    EncodedGroup encodedGroup = new EncodedGroup(HexEncoder.getBytes("fc1e0fede6e4549180dcdb91a629ea9d30fb9ab61da5f789726d5882722cab05"));

    Group group = encodedGroup.decode();

    assertThat(group.getX().getInteger(), is(new BigInteger("27443345399801550503820810706683867803355265925449420625371997396755160603300")));
    assertThat(group.getY().getInteger(), is(new BigInteger("2564001854993589394597821165299375341350553971038818461341845310541327703804")));
  }

  @Test
  public void success_DecodeGroup_15() throws DecodeException {
    EncodedGroup encodedGroup = new EncodedGroup(HexEncoder.getBytes("03cd98b81ef433956b7e2b239910450605959361e6391ebb770149693b6895c8"));

    Group group = encodedGroup.decode();

    assertThat(group.getX().getInteger(), is(new BigInteger("26579811288929527007271986534949559889238357380924397736032152196006905219455")));
    assertThat(group.getY().getInteger(), is(new BigInteger("32830504693991902250379781095167938240398939587214709772415373618962111188227")));
  }

  @Test
  public void success_DecodeGroup_16() throws DecodeException {
    EncodedGroup encodedGroup = new EncodedGroup(HexEncoder.getBytes("6c543c13177252112541e3382e5b73be26a5360e68459c87604ac53b8ac1cfcb"));

    Group group = encodedGroup.decode();

    assertThat(group.getX().getInteger(), is(new BigInteger("42949322561463186230299817970593613279310279966655824621762638884512104730735")));
    assertThat(group.getY().getInteger(), is(new BigInteger("34290536749966261157057464511838359353942848384132466399369493876322787415148")));
  }

  @Test
  public void success_DecodeGroup_17() throws DecodeException {
    EncodedGroup encodedGroup = new EncodedGroup(HexEncoder.getBytes("899c9d230f24d416647b0cfa04edc8158bb87bcd4332901cda27a979d8132a99"));

    Group group = encodedGroup.decode();

    assertThat(group.getX().getInteger(), is(new BigInteger("16119696165958767068520039407917355163375427197667342664755069949040746442291")));
    assertThat(group.getY().getInteger(), is(new BigInteger("11382165760643794875560273637359185509760076262240039946799577435076376239241")));
  }

  @Test
  public void success_DecodeGroup_18() throws DecodeException {
    EncodedGroup encodedGroup = new EncodedGroup(HexEncoder.getBytes("a13f3a02cc97ec252b785702ce5f1a201a0fc7dd177c636c5f97482af7294f5f"));

    Group group = encodedGroup.decode();

    assertThat(group.getX().getInteger(), is(new BigInteger("28991574176798270631055516789513246251336837817295903512076991779188778127680")));
    assertThat(group.getY().getInteger(), is(new BigInteger("43109591168687823035564402387271177577811433066020507559569157621096510013345")));
  }

  @Test
  public void success_DecodeGroup_19() throws DecodeException {
    EncodedGroup encodedGroup = new EncodedGroup(HexEncoder.getBytes("ebb7b4086e62dfd02dc01ab9c5c05828beb0756207aafd74a9ffc9f506f544fb"));

    Group group = encodedGroup.decode();

    assertThat(group.getX().getInteger(), is(new BigInteger("47481641482705931103934862287125658686534006637492775092431200862455707981015")));
    assertThat(group.getY().getInteger(), is(new BigInteger("55756317091645948491064284809040306721406210822346482531807933600495972956139")));
  }

  @Test
  public void success_DecodeGroup_20() throws DecodeException {
    EncodedGroup encodedGroup = new EncodedGroup(HexEncoder.getBytes("1c8dc594082e7ddad6a97f500247a585993d3b1a797041ce6f203902a7816833"));

    Group group = encodedGroup.decode();

    assertThat(group.getX().getInteger(), is(new BigInteger("43891533794047446595129048335950223439754428083113210033800244870979949519638")));
    assertThat(group.getY().getInteger(), is(new BigInteger("23252602200307492321313643524776623321052079804243872788483132543098216090908")));
  }

  @Test(expected = IllegalArgumentException.class)
  public void failure_GenerateEncodedGroup_1() {
    byte[] input = new byte[31];
    new EncodedGroup(input);
  }

  @Test(expected = IllegalArgumentException.class)
  public void failure_GenerateEncodedGroup_2() {
    byte[] input2 = new byte[33];
    new EncodedGroup(input2);
  }

  @Test(expected = DecodeException.class)
  public void failure_IllegalDecode_1() throws DecodeException {
    // BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819967")
    byte[] value = new byte[]{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 127};
    EncodedGroup encodedGroup = new EncodedGroup(value);
    encodedGroup.decode();
  }

  @Test(expected = DecodeException.class)
  public void failure_IllegalDecode_2() throws DecodeException {
    // BigInteger("56086793224325032158292195863583205366427648822419648206612267253832922169343")
    byte[] value = new byte[]{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 123};
    EncodedGroup encodedGroup = new EncodedGroup(value);
    encodedGroup.decode();
  }
}
