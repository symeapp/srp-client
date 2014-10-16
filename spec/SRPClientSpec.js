/*
 * Verification of the correctness of the SRP
 * algorithm using the official test vectors.
 * See http://tools.ietf.org/html/rfc5054#appendix-B
 */

describe("SRPClient", function() {

  var username = 'alice', password = 'password123';

  var salt = 'BEB25379D1A8581EB5A727673A2441EE';

  var srp = new SRPClient(username, password, 1024, 'sha-3');

  it("should be able to calculate k", function() {

    expect(srp.k.toString(16).toUpperCase())
    .toEqual('5E19ECC32AF1B8F813ABDC965C640152FA252E9218F4FB56260FD1608EADF67C');

  });

  var x = srp.calculateX(salt);

  it("should be able to calculate x", function() {

    expect(x.toString(16).toUpperCase())
    .toEqual('36DCCB4CCB48FFB90B74BF4A60A88FD16B284CFA7D9D0EAA73860658AD374873');

  });

  var v = srp.calculateV(salt);

  it("should be able to calculate v", function() {

    expect(v.toString(16).toUpperCase())
  .toEqual('2B4E0AEC6595FF98DD089220F3C98E1BFB3C52222F5E4061B11DD8CA071307C9A17CA648F941CB684A931289BC9760B4FFD2855ECB230A1B4A6DAE0019B230099E0E27BEDB97F54BF29E077BF5A2CBB7B9ADACF3DA2E3DEAED5F408BFBDF3904D82616E7B974092B90621A7A1439BBE204ED0064079A9A929B282B51DD3310FF');

  });

  var a = new BigInteger('60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393', 16);

  var A = srp.calculateA(a);

  it("should be able to calculate A", function() {

    expect(A.toString(16).toUpperCase())
    .toEqual('61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B');

  });

  var b = new BigInteger('E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20', 16);

  var B = srp.calculateB(b, v);

  it("should be able to calculate B", function() {

    expect(B.toString(16).toUpperCase())
    .toEqual('A0FE1AC9FD64B541CAD2C17877C1DBD1A02223B2861A29F20DACF3B26CB75A5FFDDDFC992AF86FDAD889E5E6168FFE3830A73B477AA92B3F52F1811881B4D7A1398200E1B8E3AB9776793E122B2F6CA08E42BFC38C45CEEDFD94F742EEB1EC0706430AD1569A6CDE5F1C4A4D48BC4CEBB5BC3D0DD19F4C1BEAA928C059E98432');

  });

  var u = srp.calculateU(A, B);

  it("should be able to calculate u", function() {

    expect(u.toString(16).toUpperCase())
    .toEqual('2EBC22F75A4560AE8EC009313AF379EA5D17558BF81A4F8F133CB31F6A4B996A');

  });

  var Sc = srp.calculateS(B, salt, u, a);


  it("should be able to calculate the client premaster secret", function() {

    expect(Sc.toString(16).toUpperCase())
    .toEqual('C3E774F3521DB6B2C382E4E10D39810260AD43EEFBBEEF7846EE4D22ED29C10DA4F1EE20C6726E48D32C0C2BC0FC69ADB528FAB024E4919865C6D161BF1251AA2C037F526CD5A10AA82FB0D7A5F4CB5E0A700C366B5C18E5EB4CEB2B09749F5E8396000CAC6DE20103C7B33A03FDF4BE397A380537890ACF8F8CFA460711E6B3');

  });

  var K = srp.calculateK(Sc);

  var M = srp.calculateM(A, B, K);

  it("should be able to calculate M", function () {

    expect(M.toString(16).toUpperCase())
      .toEqual('4B653F34871D93BA7470E7329E0D6660E714A34DF3249CEDFA02EB7EF9750F6C');

  });

  var Ss = srp.calculateServerS(A, v, u, b);

  it("should be able to calculate the server premaster secret", function() {

    expect(Ss.toString(16).toUpperCase())
    .toEqual('C3E774F3521DB6B2C382E4E10D39810260AD43EEFBBEEF7846EE4D22ED29C10DA4F1EE20C6726E48D32C0C2BC0FC69ADB528FAB024E4919865C6D161BF1251AA2C037F526CD5A10AA82FB0D7A5F4CB5E0A700C366B5C18E5EB4CEB2B09749F5E8396000CAC6DE20103C7B33A03FDF4BE397A380537890ACF8F8CFA460711E6B3');

  });

  it ("should match the server's premaster secret", function () {

    expect(Ss.toString(16)).toEqual(Sc.toString(16));

  });

});