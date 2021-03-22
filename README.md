## Introduction    
This package allows you to easily verify an OpenSend certificate. By default, this package will also check if it's revoked by requesting information from the OpenSend CA server (https://ca.opensend.net). This package comes with the OpenSend Authoritative Root CA certificate: you don't need to download and/or install it yourself.    

## Installing    
To install the package, run the following command:    
```
npm install @opensend/certificates
```    
You may now import the package like so:    
```js
const Certificates = require("@opensend/certificates");
```    

## Usage    
### Verifying a user certificate    
```js
const Certificates = require("@opensend/certificates");
const chain = "....";

// await
const isValid = await Certificates.verify.user(chain);

// .then
Certificates.verify.user(chain).then((isValid) => {
    // isValid is a boolean
});
```   

### Verifying a server certificate    
```js
const Certificates = require("@opensend/certificates");
const chain = "....";

// await
const isValid = await Certificates.verify.server(chain);

// .then
Certificates.verify.server(chain).then((isValid) => {
    // isValid is a boolean
});
```   

### Verifying a relay certificate    
```js
const Certificates = require("@opensend/certificates");
const chain = "....";

// await
const isValid = await Certificates.verify.relay(chain);

// .then
Certificates.verify.relay(chain).then((isValid) => {
    // isValid is a boolean
});
```   

### Verifying a peer-to-peer negotiation server certificate    
```js
const Certificates = require("@opensend/certificates");
const chain = "....";

// await
const isValid = await Certificates.verify.p2p(chain);

// .then
Certificates.verify.p2p(chain).then((isValid) => {
    // isValid is a boolean
});
```   

## API documentation
### Certificates.verify.user(chain[, check_revoked])
Verify a user/client certificate.    
 - `chain` *String*: A **full** PEM chain.
 - `check_revoked` *Boolean*: Whether to fetch the certificate's status from OpenSend.  *Default: `true`*

### Certificates.verify.server(chain[, check_revoked])
Verify a server certificate.    
 - `chain` *String*: A **full** PEM chain.
 - `check_revoked` *Boolean*: Whether to fetch the certificate's status from OpenSend.  *Default: `true`*

### Certificates.verify.relay(chain[, check_revoked])
Verify a relay certificate.    
 - `chain` *String*: A **full** PEM chain.
 - `check_revoked` *Boolean*: Whether to fetch the certificate's status from OpenSend.  *Default: `true`*

### Certificates.verify.p2p(chain[, check_revoked])
Verify a peer-to-peer negotiation server certificate.    
 - `chain` *String*: A **full** PEM chain.
 - `check_revoked` *Boolean*: Whether to fetch the certificate's status from OpenSend.  *Default: `true`*

## Credits    
### Dependencies:
- [node-forge](https://npmjs.com/package/node-forge)
- [node-fetch](https://npmjs.com/package/node-fetch)
- [split-ca](https://npmjs.com/package/split-ca)  -  Modified, built-in version. *[ISC]*    

### Developers
- Ollie Killean  -  [GitHub](https://github.com/sysollie) [Twitter](https://twitter.com/sysollie_)

## Legal    
### Brand    
OpenSend's Branding terms can be found at [https://opensend.net/brand](https://opensend.net/brand).    

### License    
```
MIT License

Copyright (c) 2021  OpenSend Technologies

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
