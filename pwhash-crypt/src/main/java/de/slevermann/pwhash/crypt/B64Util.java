/*
    Copyright 2018 Simon Levermann

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
 */
package de.slevermann.pwhash.crypt;

import java.util.regex.Pattern;

/**
 * Encoder for the B64 encoding used by crypt
 * <p>
 * Note that this is NOT a generic base64 encoder. It does not support any padding, and it uses a different
 * order than standard base64.
 *
 * @author Simon Levermann
 */
public class B64Util {

    public static final String B64_LOOKUP = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    public static final int[] B64_REVERSE = {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, -1, -1, -1, -1, -1, -1, -1, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, -1, -1, -1, -1, -1, -1, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    };
    public static final char B64_REVERSE_OFFSET = '.';

    private static final Pattern B64_PATTERN = Pattern.compile("^[0-9A-Za-z\\./]*$");

    /**
     * Encode the given bytes as a b64 string
     *
     * @param data the data to encode
     * @return the encoded String
     */
    public static String encode(byte[] data) {
        if (data.length % 3 != 0) {
            throw new IllegalArgumentException("Input length not divisible by 3");
        }
        StringBuilder output = new StringBuilder((data.length / 3) * 4);
        for (int i = 0; i < data.length; i += 3) {
            int b0 = data[i] & 0xff;
            int b1 = data[i + 1] & 0xff;
            int b2 = data[i + 2] & 0xff;
            int w = (b2 << 16) | (b1 << 8) | b0;
            for (int j = 0; j < 4; j++) {
                output.append(B64_LOOKUP.charAt(w & 0b111111));
                w >>>= 6;
            }
        }
        return output.toString();
    }

    /**
     * Decode the given b64 string to bytes
     *
     * @param data the data to decode
     * @return the decoded String
     */
    public static byte[] decode(String data) {
        if (data.length() % 4 != 0) {
            throw new IllegalArgumentException("Input length not divisible by 4");
        }

        if (!B64_PATTERN.matcher(data).matches()) {
            throw new IllegalArgumentException("Input is not valid B64");
        }

        byte[] res = new byte[data.length() / 4 * 3];
        int offset = 0;
        for (int i = 0; i < data.length(); i += 4) {
            int b0 = B64_REVERSE[data.charAt(i) - B64_REVERSE_OFFSET];
            int b1 = B64_REVERSE[data.charAt(i + 1) - B64_REVERSE_OFFSET];
            int b2 = B64_REVERSE[data.charAt(i + 2) - B64_REVERSE_OFFSET];
            int b3 = B64_REVERSE[data.charAt(i + 3) - B64_REVERSE_OFFSET];

            int val = (b3 << 18) | (b2 << 12) | (b1 << 6) | b0;
            res[offset++] = (byte) val;
            res[offset++] = (byte) (val >>> 8);
            res[offset++] = (byte) (val >>> 16);
        }
        return res;
    }
}
