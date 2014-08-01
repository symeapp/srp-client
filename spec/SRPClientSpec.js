/*
 * Verification of the correctness of the SRP
 * algorithm using the official test vectors.
 * See http://tools.ietf.org/html/rfc5054#appendix-B
 */
 
describe("SRPClient", function() {

  var username = 'USER010', password = 'hello';
  
  var salt = '41C832064DDD57247406AEC800E9A00A';

  var srp = new SRPClient(username, password, 1024, 'sha-256');

  it("should be able to calculate k", function() {

    expect(srp.k.toString(16).toUpperCase())
    .toEqual('1A1A4C140CDE70AE360C1EC33A33155B1022DF951732A476A862EB3AB8206A5C');
	//Srp6Utilities.CalculateK(digest, N, g);
    
  });

  var x = srp.calculateX(salt);

  it("should be able to calculate x", function() {

    expect(x.toString(16).toUpperCase())
    .toEqual('A801BC3018039BC164F794B05F7D591A2EF5628FE024B3328C863D4E2933F8C5'); 
	//Srp6Utilities.CalculateX(digest, N, b_salt, b_identity, b_password);
    
  });

  var v = srp.calculateV(salt);

  it("should be able to calculate v", function() {

    expect(v.toString(16).toUpperCase())
  .toEqual('BEBE1D36464A37A35CF3D432F947532B91CE5F10A8A2BFC4B4AAD754334AD51FBBB1C49E5842C84BAFC1D75D74C370BCB5CE6802C174072719E1AEB895A1FCABF85D159E0EF2AC7907A2833E0650A8690BD900F4C0F1E8FEC9367F7C6C3E70B0D26B2756104434A675BD7A2E803CA13DBCB4B4C62889CCA446D8371DED6844C9');
  // g.ModPow(x, N) in Srp6Client.CalculateS()
    
  });
  
  var a = new BigInteger('60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393', 16); //Srp6Client.SelectPrivateValue(); Random Generated

  var A = srp.calculateA(a);

  it("should be able to calculate A", function() {
    expect(A.toString(16).toUpperCase())
    .toEqual('61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B');
    //pubA = g.ModPow(privA, N);
  });
  
  var B = new BigInteger('D6549BA2A155B282176E0A2A97512E2D42D55675D1082135BA59734C00C5C7FB8333BA0B4539F78005A4DE31AC4362DB73C3DEDDACA845ABD0C2595921F0457DC9DF0F484B2436CD1D3E41526DD060ED09465E599F9EFCA53429C8369D9D7B295DE149B8C898B2CD122390D12E6898B1653A5A9CC91F3816F8C89F59E448BE3D', 16);
  
  var u = srp.calculateU(A, B);

  it("should be able to calculate u", function() {

    expect(u.toString(16).toUpperCase())
    .toEqual('E1D7C7657FC0FA3E631256144FFE8A7E9D03114AACD2F589C010EF4EF83DBED');
    //Srp6Utilities.CalculateU(digest, N, pubA, B)
  });
  
  var Sc = srp.calculateS(B, salt, u, a);
    
  it("should be able to calculate the client premaster secret", function() {

    expect(Sc.toString(16).toUpperCase())
    .toEqual('67CCF122FA865E1411AA010A034F55B799B626317A8405583FC64FAF2493410E22A09F7B18D9152ECE8C78D4CA21B356B9BCA7120AA2A44DF1A7BBC94305503D93EF00DDD2C904526DC767C307A784AFD3CBFBE640A0D1B69F502FD3B1DFBFD0140382CEB8D9C90E3B50780491831EF1539BA47B08C3FD6BD48A69E853D7F0B0');
    
  });
  
  var K = srp.calculateK(Sc);
  it("should be able to calculate K_C", function() {

    expect(K.toUpperCase())
    .toEqual('0A56A52B3ADF853BDB69404043172A545EF6EDBC77F1BA2F92E63641A040BD16');
    //GetHexEncodedStringFromBytes(clientKey.ToByteArrayUnsigned());
  });
  
  
  var M = srp.concastMc(salt, A, B, K);

  it("should be able to calculate Mc", function () {
    
    expect(M.toUpperCase())
      .toEqual('3AEB0F9D9F82C9613703F53CBEB1CAF38772E10239D11B2FB62CDB1D85B2ABE6');
    
  });
  
  
  var Ss = srp.concastMs(A, M, K);
  //Once you get another SS from the Server Side, compare it with Ss. 

  it("should be able to calculate the server premaster secret", function() {

    expect(Ss.toUpperCase())
    .toEqual('83B3F65EB44314497DA388BBDF9D43EEEADB9BEDF0CA8005C846CDD09C050294');
    
  });
});