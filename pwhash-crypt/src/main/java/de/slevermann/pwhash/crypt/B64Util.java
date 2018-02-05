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

    /**
     * Encode the given bytes as a b64 string
     *
     * @param data the data to encode
     * @return the encoded String
     */
    public static String encode(byte[] data) {
        return null;
    }

    /**
     * Decode the given b64 string to bytes
     *
     * @param data the data to decode
     * @return the decoded String
     */
    public static byte[] decode(String data) {
        return null;
    }
}
