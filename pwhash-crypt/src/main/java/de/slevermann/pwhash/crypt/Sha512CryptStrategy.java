package de.slevermann.pwhash.crypt;

public class Sha512CryptStrategy extends ShaCryptStrategy {
    /**
     * Create a new shacrypt instance with the given rounds and salt length
     *
     * @param rounds     the number of rounds to use for hashing, should be between 1000 and 999,999,999. Incorrect values are
     *                   automatically corrected as per the specification
     * @param saltLength length of the salt to use.
     */
    protected Sha512CryptStrategy(int rounds, int saltLength) {
        super("SHA512", rounds, saltLength);
    }

    @Override
    protected byte[] shuffle(byte[] data) {
        byte[] output = new byte[66];
        output[2] = data[0];
        output[1] = data[21];
        output[0] = data[42];

        output[5] = data[22];
        output[4] = data[43];
        output[3] = data[1];

        output[8] = data[44];
        output[7] = data[2];
        output[6] = data[23];

        output[11] = data[3];
        output[10] = data[24];
        output[9] = data[45];

        output[14] = data[25];
        output[13] = data[46];
        output[12] = data[4];

        output[17] = data[47];
        output[16] = data[5];
        output[15] = data[26];

        output[20] = data[6];
        output[19] = data[27];
        output[18] = data[48];

        output[23] = data[28];
        output[22] = data[49];
        output[21] = data[7];

        output[26] = data[50];
        output[25] = data[8];
        output[24] = data[29];

        output[29] = data[9];
        output[28] = data[30];
        output[27] = data[51];

        output[32] = data[31];
        output[31] = data[52];
        output[30] = data[10];

        output[35] = data[53];
        output[34] = data[11];
        output[33] = data[32];

        output[38] = data[12];
        output[37] = data[33];
        output[36] = data[54];

        output[41] = data[34];
        output[40] = data[55];
        output[39] = data[13];

        output[44] = data[56];
        output[43] = data[14];
        output[42] = data[35];

        output[47] = data[15];
        output[46] = data[36];
        output[45] = data[57];

        output[50] = data[37];
        output[49] = data[58];
        output[48] = data[16];

        output[53] = data[59];
        output[52] = data[17];
        output[51] = data[38];

        output[56] = data[18];
        output[55] = data[39];
        output[54] = data[60];

        output[59] = data[40];
        output[58] = data[61];
        output[57] = data[19];

        output[62] = data[62];
        output[61] = data[20];
        output[60] = data[41];

        output[65] = 0;
        output[64] = 0;
        output[63] = data[63];

        return output;
    }
}
