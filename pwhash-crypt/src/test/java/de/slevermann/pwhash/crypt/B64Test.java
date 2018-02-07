package de.slevermann.pwhash.crypt;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.Random;


public class B64Test {

    private Random random = new Random();

    @DataProvider
    Object[][] invalidLengthStrings() {
        return new Object[][]{
                {"a"},
                {"aaaaa"},
                {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
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


    @Test(invocationCount = 100)
    public void testEncodeRemainderOne() {
        int inputLength;
        do {
            inputLength = random.nextInt(100);
        } while (inputLength % 3 != 1);

        byte[] data = new byte[inputLength];
        random.nextBytes(data);

        String output = B64Util.encode(data);

        int expectedLength = ((inputLength - 1) / 3) * 4 + 2;

        Assert.assertEquals(output.length(), expectedLength, "Single trailing byte should produce 2 trailing characters");
    }

    @Test(invocationCount = 100)
    public void testEncodeRemainderTwo() {
        int inputLength;
        do {
            inputLength = random.nextInt(100);
        } while (inputLength % 3 != 2);

        byte[] data = new byte[inputLength];
        random.nextBytes(data);

        String output = B64Util.encode(data);

        int expectedLength = ((inputLength - 2) / 3) * 4 + 3;

        Assert.assertEquals(output.length(), expectedLength, "Single trailing byte should produce 3 trailing characters");
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

    @Test(invocationCount = 100)
    public void testDecodeRemainderTwo() {
        int inputLength;
        do {
            inputLength = random.nextInt(100);
        } while (inputLength % 4 != 2);

        StringBuilder sb = new StringBuilder(inputLength);
        for (int i = 0; i < inputLength; i++) {
            int index = random.nextInt(B64Util.B64_LOOKUP.length());
            sb.append(B64Util.B64_LOOKUP.charAt(index));
        }

        String data = sb.toString();
        byte[] decoded = B64Util.decode(data);

        int expectedLength = ((inputLength - 2) / 4) * 3 + 1;

        Assert.assertEquals(decoded.length, expectedLength, "Decoding 2 trailing characters should yield one trailing byte");
    }

    @Test(invocationCount = 100)
    public void testDecodeRemainderThree() {
        int inputLength;
        do {
            inputLength = random.nextInt(100);
        } while (inputLength % 4 != 3);

        StringBuilder sb = new StringBuilder(inputLength);
        for (int i = 0; i < inputLength; i++) {
            int index = random.nextInt(B64Util.B64_LOOKUP.length());
            sb.append(B64Util.B64_LOOKUP.charAt(index));
        }

        String data = sb.toString();
        byte[] decoded = B64Util.decode(data);

        int expectedLength = ((inputLength - 2) / 4) * 3 + 2;

        Assert.assertEquals(decoded.length, expectedLength, "Decoding 3 trailing characters should yield two trailing bytes");
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