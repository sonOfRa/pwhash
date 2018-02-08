package de.slevermann.pwhash.crypt;

import org.testng.annotations.DataProvider;

public class Sha512CryptTest extends ShaCryptTest {

    @DataProvider
    @Override
    public Object[][] externalHashes() {
        return new Object[][]{
                {"asdf", "$6$bIu8S0T.VgPU4$EYhOi7nUch5vm.Hh116Cv9TzWX5sdVjJjh1END/z/2kkT5BWiRUPtJgS/OJJ4.c1aFuw04VcmVst7tGmQd79r0"},
                {"asdf", "$6$rounds=1000$MJf9/UWX$GRKqx.7lZqS9P7995jmt.pqcjP.Zv/VA/Xadn.LlXpgoME1rvsNS3J0Pi4l9Sa4v23qV8DDD.xjYqBsEyhfi9."},
                {"asdf", "$6$rounds=5000$/XTeXWBUpFItpP$qEEsFUK9WO6gXovXDFxaewZaYxZD06DQ87nzTfUK60csoACiKBDAAgwoP4Yc9VN3c5Xzexx.VDOkAQSykHI2d/"},
                {"asdf", "$6$rounds=100000$J2gEsaP6Ukr.p$BpuPaf0nI2dmjy2b0V4pjp2qQzRH7FG/pAreQWn3qKBBd1kFEKchiemAhKrq9RrTY7/KK4d3PZh7DxIME33QK/"},
                {"thisisaverylongpassword", "$6$IJHFIZSm6my2mQM7$3zNDqWwod9t.wV9icqXQxPHHayJqOXdBp1LoJmh3M8q0jUC0gBDSufX7zsq/lrK.2l/GnWhxZswq5cuv2By0s."},
                {"thisisaverylongpassword", "$6$rounds=1000$PHMhCnli9v$XX.ShTm.hmqVhvbVgwJw05NQcAeg4eneu7ZGyxvUF/LrBu4.1X7hbEeyoHYCfbH4aZs0bPaVfyDELNultABr91"},
                {"thisisaverylongpassword", "$6$rounds=5000$w4UdUwcbRl$nohyI07wh50RuGBRqVxPVAhaQJjvQLATru2DQ.fUlx58istICvnuslvheMVo83CrN4v3IhX/kHQKiLj8e31pn."},
                {"thisisaverylongpassword", "$6$rounds=100000$IxfWVffPCWSZAjL$SoJY9uhhtIZ8X/K4jMH8qdDmMEzlbX4/a44qN7fCNeVOHxcK4dluU1DG//MW8TzgJO09MuMd13x22PrDFrh491"},
        };
    }

    public Sha512CryptTest() {
        this.s = new Sha512CryptStrategy();
    }

}
