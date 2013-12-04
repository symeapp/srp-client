/*
 * Verification of the correctness of the SRP
 * algorithm using the official test vectors.
 * See http://tools.ietf.org/html/rfc5054#appendix-B
 */
 
describe("SRPClient", function() {

  var username = 'alice', password = 'password123';
  
  var salt = 'BEB25379D1A8581EB5A727673A2441EE';

  var srp = new SRPClient(username, password, 1024, 'sha-1');

  it("should be able to calculate k", function() {

    expect(srp.k.toString(16).toUpperCase())
    .toEqual('7556AA045AEF2CDD07ABAF0F665C3E818913186F');
    
  });

  var x = srp.calculateX(salt);

  it("should be able to calculate x", function() {

    expect(x.toString(16).toUpperCase())
    .toEqual('94B7555AABE9127CC58CCF4993DB6CF84D16C124');
    
  });

  var v = srp.calculateV(salt);

  it("should be able to calculate v", function() {

    expect(v.toString(16).toUpperCase())
  .toEqual('7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D8129BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78E955A5E29E7AB245DB2BE315E2099AFB');
    
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
    .toEqual('BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B117B58');
    
  });

  var u = srp.calculateU(A, B);

  it("should be able to calculate u", function() {

    expect(u.toString(16).toUpperCase())
    .toEqual('CE38B9593487DA98554ED47D70A7AE5F462EF019');
    
  });
  
  var Sc = srp.calculateS(B, salt, u, a);
  
  
  it("should be able to calculate the client premaster secret", function() {

    expect(Sc.toString(16).toUpperCase())
    .toEqual('B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A');
    
  });
  
  var K = srp.calculateK(Sc);
  
  var M = srp.calculateM(A, B, K);

  it("should be able to calculate M", function () {
    
    expect(M.toString(16).toUpperCase())
      .toEqual('E5F39493B07B8B88E2A4F44BC9282874CD2DEBED');
    
  });

  var Ss = srp.calculateServerS(A, v, u, b);

  it("should be able to calculate the server premaster secret", function() {

    expect(Ss.toString(16).toUpperCase())
    .toEqual('B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A');
    
  });
  
  it ("should match the server's premaster secret", function () {
    
    expect(Ss.toString(16)).toEqual(Sc.toString(16));
    
  });

});