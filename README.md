### Javascript Client for the Secure Remote Protocol (SRP)

_**Warning**: this is an alpha release and is not ready for production use. Peer review is appreciated.

_**Known Vulnerabilities**_

- The default PRNG included with this distribution does not rely on sufficiently random sources of entropy (see issue #1).
- Proper parameter validation is not implemented (see issue #2).

This library implements a Javascript client for the SRP protocol. The client aims to be compatible with SRP revision 6A, as defined in [RFC 5054](http://tools.ietf.org/html/rfc5054) ("Using the Secure Remote Password (SRP) Protocol for TLS Authentication"). It is released under the MPL.

The code is directly based on Tom Wu's [Javascript SRP demo](http://srp.stanford.edu/demo/demo.html), which is released under the [SRP license](http://srp.stanford.edu/license.txt).

### Testing

This library is tested with Jasmine using the [official test vectors](http://tools.ietf.org/html/rfc5054#appendix-B) from the SRP specification. The specs can be run by opening `SpecRunner.html` in your browser.

### Usage

**Configuration**

As shown in the examples below, this library accepts 1024, 1536, 2048, 4096, 6144 and 8192-bit group parameters. The default is 1024 bits.

**Registration Example**

```html
<html>

<head>
  
  <script type="text/javascript" src="jsbn.js"></script>
  <script type="text/javascript" src="sha1.js"></script>
  <script type="text/javascript" src="random.js"></script>
  <script type="text/javascript" src="srp-client.js"></script>

  <script type="text/javascript">

  var bits     =  2048;
  var username = 'username';
  var password = 'password';

  var srp = new SRPClient(username, password, bits);

  // 1. The client generates a random hex salt.
  var s = srp.randomHexSalt();
  
  // 2. The client calculates its verifier value.
  var v = srp.calculateV(salt);
  
  // 3. The client sends the username, salt and
  // verifier to the server, which stores all three.
  
  </script>

</head>

</html>
```

**Authentication Example**

```html
<html>

<head>

  <script type="text/javascript" src="jsbn.js"></script>
  <script type="text/javascript" src="sha1.js"></script>
  <script type="text/javascript" src="random.js"></script>
  <script type="text/javascript" src="srp-client.js"></script>

  <script type="text/javascript">
  
  var username = 'username';
  var password = 'password';

  var srp = new SRPClient(username, password, 2048);

  // 1. The client generates and stores A.
  var a = srp.srpRandom();
  var A = srp.calculateA(a);

  // 2. The client sends A to the server.
  
  // 3. The server receives A and generates B.
  var b = srp.srpRandom();
  var B = srp.calculateB(b);

  // 4. The client and the server both calculate U.
  var u = srp.calculateU(A, B);

  // 5. The client generates its premaster secret.
  var Sc = srp.calculateS(B, salt, u, a);
  
  // 6. The server generates its premaster secret.
  var Ss = srp.calculateServerS(A, v, u, b);

  // 7. The client and the server verify the secrets.
  console.log('Server and client secrets match:');
  console.log(Sc.toString() == Ss.toString());

  </script>

</head>

</html>
```

### Further Reading

- RFC 2945 - The SRP Authentication and Key Exchange System
- RFC 5054 - Using the Secure Remote Password (SRP) Protocol for TLS Authentication

### License

This library is released under the MPL.
