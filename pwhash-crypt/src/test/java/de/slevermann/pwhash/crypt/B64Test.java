package de.slevermann.pwhash.crypt;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.Random;

import static de.slevermann.pwhash.crypt.B64Util.B64_LOOKUP;


public class B64Test {

    private Random random = new Random();

    @DataProvider
    Object[][] invalidByteArrays() {
        return new Object[][]{
                {new byte[1]},
                {new byte[2]},
                {new byte[4]},
                {new byte[7]},
                {new byte[3 * 100 + 1]},
                {new byte[3 * 100 + 2]},
        };
    }

    @DataProvider
    Object[][] invalidLengthStrings() {
        return new Object[][]{
                {"a"},
                {"aa"},
                {"aaa"},
                {"aaaaa"},
                {"aaaaaa"},
                {"aaaaaaa"},
                {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        };
    }

    @DataProvider
    Object[][] invalidCharacterStrings() {
        return new Object[][]{
                {"ääää"},
                {"    "},
                {"||||"},
                {"&&&&"},
                {"...ö"},
                {"ö..."},
                {".ö.."},
        };
    }

    @Test
    public void testEncodeEmpty() {
        byte[] empty = new byte[0];

        String encoded = B64Util.encode(empty);

        Assert.assertEquals(encoded.length(), 0, "Encoded string for empty byte array should be empty");
    }

    @Test(dataProvider = "invalidByteArrays", expectedExceptions = IllegalArgumentException.class)
    public void testEncodeInvalidLength(byte[] data) {
        B64Util.encode(data);
    }

    @Test
    public void testEncodeZeros() {
        byte[] zeros = new byte[3 * 5];

        String zerosEncoded = B64Util.encode(zeros);
        Assert.assertEquals(zerosEncoded, "....................", "Zeros should encode to just dots");
    }


    @Test
    public void testDecodeEmpty() {
        String empty = "";

        byte[] decoded = B64Util.decode(empty);

        Assert.assertEquals(decoded.length, 0, "Decoded byte array for empty string should be empty");
    }

    @Test
    public void testDecodeDots() {
        String dots = "....................";

        byte[] dotsDecoded = B64Util.decode(dots);
        Assert.assertEquals(dotsDecoded, new byte[3 * 5], "Dots should decode to just zeros");
    }

    @Test(dataProvider = "invalidLengthStrings", expectedExceptions = IllegalArgumentException.class)
    public void testDecodeInvalidLengthStrings(String data) {
        B64Util.decode(data);
    }

    @Test(dataProvider = "invalidCharacterStrings", expectedExceptions = IllegalArgumentException.class)
    public void testDecodeInvalidCharacterStrings(String data) {
        B64Util.decode(data);
    }

    @Test(invocationCount = 100)
    public void testBackAndForth() {
        int length;
        do {
            length = random.nextInt(100);
        } while (length % 3 != 0);

        byte[] data = new byte[length];

        random.nextBytes(data);

        String encoded = B64Util.encode(data);

        byte[] decoded = B64Util.decode(encoded);

        Assert.assertEquals(decoded, data);
    }
}