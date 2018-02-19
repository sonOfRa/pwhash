package de.slevermann.pwhash.crypt;

import org.testng.annotations.DataProvider;

public class Sha256CryptTest extends ShaCryptTest {

    @DataProvider
    @Override
    public Object[][] externalHashes() {
        return new Object[][]{
                {"asdf", "$5$s5PL1I/19hr0cSVO$SjeqzE0tdlN9SiVkXrhbdUbAsnL0GQKe8jZZSdmWNT5"},
                {"asdf", "$5$rounds=1000$.A1KNh3MI5Oy$IM0v9lDahQJTGSekckzi/gmgl6XI.lK7mU8g5xmcxVD"},
                {"asdf", "$5$rounds=5000$cTudmPLG$4qbzYy/v6CibqmdhneV4f8jYYiMTt9snTMND29xBywA"},
                {"asdf", "$5$rounds=100000$gdeGbuSy$ENjDFPJCz..STQGHoK9n2uPsMHZCV3ES/H0If.ooQw7"},
                {"thisisaverylongpassword", "$5$TXclidmEjfAd$edL7CmbYg8Ed5QAxKjmus7tZUsNmYRB3..A8XKMrJk3"},
                {"thisisaverylongpassword", "$5$rounds=1000$GkBZn8Dn4pPW$yGeVhyLW/nDZtrxLoBPLINs98dV67b8pzj90TM6bf3/"},
                {"thisisaverylongpassword", "$5$rounds=5000$qspLSFg.W5MEHqtz$e/3bAsGaEZijUs0xfDfjEAFsiPNqkRiAB5T8b7Q/aG5"},
                {"thisisaverylongpassword", "$5$rounds=100000$EeecDZi0iFz$Qhpc.HmB0CAgct/zOLHu5F7T1F3AYUeKZUNBGDZdfP2"},
        };
    }

    @DataProvider
    @Override
    protected Object[][] invalidSaltCharacters() {
        return new Object[][]{
                {"$5$ÄÖÜ$SjeqzE0tdlN9SiVkXrhbdUbAsnL0GQKe8jZZSdmWNT5"},
        };
    }

    @DataProvider
    @Override
    protected Object[][] badSaltId() {
        return new Object[][]{
                {"$6$TXclidmEjfAd$edL7CmbYg8Ed5QAxKjmus7tZUsNmYRB3..A8XKMrJk3"},
                {"5$TXclidmEjfAd$edL7CmbYg8Ed5QAxKjmus7tZUsNmYRB3..A8XKMrJk3"},
        };
    }

    public Sha256CryptTest() {
        this.defaultStrategy = new Sha256CryptStrategy();
        this.customRoundsStrategy = new Sha256CryptStrategy(ShaCryptStrategy.DEFAULT_ROUNDS * 2,
                CryptStrategy.DEFAULT_SALT_LENGTH);
        this.customSaltStrategy = new Sha256CryptStrategy(ShaCryptStrategy.DEFAULT_ROUNDS,
                CryptStrategy.DEFAULT_SALT_LENGTH / 2);
    }
}
