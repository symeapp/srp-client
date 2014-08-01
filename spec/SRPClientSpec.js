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
    .toEqual('339D2399B4381B937C3ED0AD2EA7DAAE13D232D881C9E6B2CF1AAC41CA6BF9C5'); 
	//Srp6Utilities.CalculateX(digest, N, b_salt, b_identity, b_password);
    
  });

  var v = srp.calculateV(salt);

  it("should be able to calculate v", function() {

    expect(v.toString(16).toUpperCase())
  .toEqual('8A0D080D563D4201C56A5E0679825D0386D338F951AE9197BB1F0867BD318BDEEAD29626AB2AFDD27DCDEE9663EDBB3397E3E831AD641C453073E6D282C14E0D84C56AD5B5D2509232D8E2562907A6374573ECEEC0B028780D8F1F29659D4B38CB28A38E80E3AA47B651A02333D6FE71B3EBB3353AACE13E55BEDA8F83C9657B');
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
    .toEqual('3F24543F4FB2F6146738937CB41CD67175DA9E17D42CD7E8AED57DADDA619CCBFDC970F04129D3D3B9F9FD74F544B83932494ED8E6A1771961D1508BD6CF0761B298371DEFBC614D0A40B54161F33DAC4AB756C011998D6B5423B500A62A0834F87C93EA2C4581C42E42214D5A7AB3EFF36F1B46104BE7AF9885B6D573330A74');
    
  });
  
  var K = srp.calculateK(Sc);
  it("should be able to calculate K_C", function() {

    expect(K.toUpperCase())
    .toEqual('491AFA37ECC787E61AB84BE8FF8C16086C2FF3FF51D7A37F9FF03FC3AEB3B7DA');
    //GetHexEncodedStringFromBytes(clientKey.ToByteArrayUnsigned());
  });
  
  
  var M = srp.concastMc(salt, A, B, K);

  it("should be able to calculate Mc", function () {
    
    expect(M.toUpperCase())
      .toEqual('13791ABAFB9FA21C360D1EB3FBD4F6E195C0B2F558EFB45F93AD518AA3F87294');
    
  });
  
  
  var Ss = srp.concastMs(A, M, K);
  //Once you get another SS from the Server Side, compare it with Ss. 

  it("should be able to calculate the server premaster secret", function() {

    expect(Ss.toUpperCase())
    .toEqual('83B3F65EB44314497DA388BBDF9D43EEEADB9BEDF0CA8005C846CDD09C050294');
    
  });
});