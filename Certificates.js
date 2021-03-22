/*
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
*/


// Yes, I'm aware this file is a mess, but it does its job.

const Forge = require("node-forge"),
    fetch = require("node-fetch");

module.exports.verify = {
    user: async (chain, checkRevoked) => {
        /*
            * <b>chain</b> string: The full certificate chain.<br>
            * <b>checkRevoked</b>? boolean: Whether to pull revokation statuses from a remote server. (Default: true)
        */

        if (!chain || typeof chain !== 'string') throw new TypeError("Chain must be a string.");
        if (checkRevoked !== false) checkRevoked = true;

        chain = _load(chain);
        const now = Date.now();
        isChainValid = true;

        // Check certificates are all valid.
        for (let i = 0;chain.length > i;i++) {
            try {
                let cert = chain[i];
                let notBefore = new Date(cert.notBefore).getTime();
                let notAfter = new Date(cert.notAfter).getTime();
                let hash = _hash(Forge.pki.certificateToPem(cert));
                let basicConstraints = cert.extensions.find(v => v.name === "basicConstraints");

                // Check the certificate isn't expired...
                if (notAfter - now < 0) throw new Error("A certificate in the chain has expired.");

                // If the certificate is an issuer...
                if (i !== 0) {
                    // Check the certificate is an authorised CA.
                    if (!basicConstraints.cA) throw new Error("An issuing certificate has not been authorised as a certificate authority, but has attempted to act as one.");

                    // If the issuer authorized a CA...
                    if (chain[i - 2]) {
                        let chainLength = 0;
                        let past = false;

                        // If there is a path length constraint...
                        let pathLenConstraint = basicConstraints.pathLenConstraint;
                        if (pathLenConstraint) {
                            // Check that the issuer can issue further certificates.
                            if (pathLenConstraint < 0) throw new Error("An issuing certificate has authorized further certificate authorities whilst being disallowed from doing so.");

                            // Go through the certification path...
                            for (let ii = chain.length;ii > 0;ii--) {
                                let belowCert = chain[ii];
                                if (belowCert === cert) {
                                    past = true;
                                    continue;
                                }

                                if (!past) continue;

                                let belowBasicConstraints = belowCert.extensions.find(v => v.name === "basicConstraints");
                                if (belowBasicConstraints.cA) chainLength++;
                            }

                            // Make sure the certification path isn't too long.
                            if (chainLength > pathLenConstraint) throw new Error("An issuing certificate's chain is too long.");
                        }
                    }

                    // If the issuer isn't root...
                    if (i < chain.length - 1) {
                        let issuer = chain[i + 1];

                        // Check that is was signed by it's issuer.
                        try {
                            if (!issuer.verify(cert)) throw new Error();
                        } catch (err) {
                            throw new Error("An issuing certificate was not signed by it's apparent issuer.");
                        }

                        // Check that it was signed after the issuer was authorized.
                        if (notBefore - new Date(issuer.notBefore).getTime() < 0) throw new Error("An issuer's certificate was authorized before it's issuer was.");
                    }

                    // If the issuer is root...
                    if (i === chain.length - 1) {
                        // Check it is actually the OpenSend root.
                        let knownRoot = Forge.pki.certificateFromPem(ROOT());
                        if (Forge.pki.certificateToPem(cert) !== Forge.pki.certificateToPem(knownRoot)) throw new Error("The provided root certificate does not match the OpenSend Authoritative Root CA.")

                        // Check it was issued by itself.
                        try {
                            if (!knownRoot.verify(cert)) throw new Error();
                        } catch (err) {
                            throw new Error("The root certificate was not issued to itself.");
                        }
                    }

                    // If the certificate is an authoritative intermediate...
                    if (cert.subject.attributes.find(v => v.name === "commonName").value.includes("Authoritative Intermediate")) {
                        // Check that it's in the right position.
                        if (i !== chain.length - 2) throw new Error("A certificate incorrectly identifies itself as an authoritative intermediate.");

                        // Check it's the right authoritative intermediate.
                        if (!cert.subject.attributes.find(v => v.name === "commonName").value.startsWith("OpenSend User Authentication")) throw new Error("A certificate has been used incorrectly.");
                    }
                } else { // If the certificate is the end entity...
                    // Check it was signed by it's issuer.
                    try {
                        if (!chain[1].verify(cert)) throw new Error();
                    } catch (err) {
                        throw new Error("The end entity certificate was not signed by it's issuer.");
                    }
                }

                // Finally, check the certificate isn't revoked:
                let valid = true;
                if (checkRevoked) {
                    valid = await new Promise((resolve) => {
                        fetch("https://ca.opensend.net/users/" + hash + ".json").then(x => x.json()).then((res) => {
                            if (!res.exists || res.revoked) resolve(false);
                            resolve(true);
                        }).catch((err) => {
                            console.error(err);
                            resolve(false)
                        });
                    });
                }

                if (!valid) isChainValid = false;
            } catch (err) {
                console.error("Error:");
                throw err;
            }
        }

        return isChainValid;
    },
    server: async (chain, checkRevoked) => {
        /*
            * <b>chain</b> string: The full certificate chain.<br>
            * <b>checkRevoked</b>? boolean: Whether to pull revokation statuses from a remote server. (Default: true)
        */

        if (!chain || typeof chain !== 'string') throw new TypeError("Chain must be a string.");
        if (checkRevoked !== false) checkRevoked = true;

        chain = _load(chain);
        const now = Date.now();
        isChainValid = true;

        // Check certificates are all valid.
        for (let i = 0;chain.length > i;i++) {
            try {
                let cert = chain[i];
                let notBefore = new Date(cert.notBefore).getTime();
                let notAfter = new Date(cert.notAfter).getTime();
                let hash = _hash(Forge.pki.certificateToPem(cert));
                let basicConstraints = cert.extensions.find(v => v.name === "basicConstraints");

                // Check the certificate isn't expired...
                if (notAfter - now < 0) throw new Error("A certificate in the chain has expired.");

                // If the certificate is an issuer...
                if (i !== 0) {
                    // Check the certificate is an authorised CA.
                    if (!basicConstraints.cA) throw new Error("An issuing certificate has not been authorised as a certificate authority, but has attempted to act as one.");

                    // If the issuer authorized a CA...
                    if (chain[i - 2]) {
                        let chainLength = 0;
                        let past = false;

                        // If there is a path length constraint...
                        let pathLenConstraint = basicConstraints.pathLenConstraint;
                        if (pathLenConstraint) {
                            // Check that the issuer can issue further certificates.
                            if (pathLenConstraint < 0) throw new Error("An issuing certificate has authorized further certificate authorities whilst being disallowed from doing so.");

                            // Go through the certification path...
                            for (let ii = chain.length;ii > 0;ii--) {
                                let belowCert = chain[ii];
                                if (belowCert === cert) {
                                    past = true;
                                    continue;
                                }

                                if (!past) continue;

                                let belowBasicConstraints = belowCert.extensions.find(v => v.name === "basicConstraints");
                                if (belowBasicConstraints.cA) chainLength++;
                            }

                            // Make sure the certification path isn't too long.
                            if (chainLength > pathLenConstraint) throw new Error("An issuing certificate's chain is too long.");
                        }
                    }

                    // If the issuer isn't root...
                    if (i < chain.length - 1) {
                        let issuer = chain[i + 1];

                        // Check that is was signed by it's issuer.
                        try {
                            if (!issuer.verify(cert)) throw new Error();
                        } catch (err) {
                            throw new Error("An issuing certificate was not signed by it's apparent issuer.");
                        }

                        // Check that it was signed after the issuer was authorized.
                        if (notBefore - new Date(issuer.notBefore).getTime() < 0) throw new Error("An issuer's certificate was authorized before it's issuer was.");
                    }

                    // If the issuer is root...
                    if (i === chain.length - 1) {
                        // Check it is actually the OpenSend root.
                        let knownRoot = Forge.pki.certificateFromPem(ROOT());
                        if (Forge.pki.certificateToPem(cert) !== Forge.pki.certificateToPem(knownRoot)) throw new Error("The provided root certificate does not match the OpenSend Authoritative Root CA.")

                        // Check it was issued by itself.
                        try {
                            if (!knownRoot.verify(cert)) throw new Error();
                        } catch (err) {
                            throw new Error("The root certificate was not issued to itself.");
                        }
                    }

                    // If the certificate is an authoritative intermediate...
                    if (cert.subject.attributes.find(v => v.name === "commonName").value.includes("Authoritative Intermediate")) {
                        // Check that it's in the right position.
                        if (i !== chain.length - 2) throw new Error("A certificate incorrectly identifies itself as an authoritative intermediate.");

                        // Check it's the right authoritative intermediate.
                        if (!cert.subject.attributes.find(v => v.name === "commonName").value.startsWith("OpenSend Server Authentication")) throw new Error("A certificate has been used incorrectly.");
                    }
                } else { // If the certificate is the end entity...
                    // Check it was signed by it's issuer.
                    try {
                        if (!chain[1].verify(cert)) throw new Error();
                    } catch (err) {
                        throw new Error("The end entity certificate was not signed by it's issuer.");
                    }
                }

                // Finally, check the certificate isn't revoked:
                let valid = true;
                if (checkRevoked) {
                    valid = await new Promise((resolve) => {
                        fetch("https://ca.opensend.net/servers/" + hash + ".json").then(x => x.json()).then((res) => {
                            if (!res.exists || res.revoked) resolve(false);
                            resolve(true);
                        }).catch((err) => {
                            console.error(err);
                            resolve(false)
                        });
                    });
                }

                if (!valid) isChainValid = false;
            } catch (err) {
                console.error("Error:");
                throw err;
            }
        }

        return isChainValid;
    },
    relay: async (chain, checkRevoked) => {
        /*
            * <b>chain</b> string: The full certificate chain.<br>
            * <b>checkRevoked</b>? boolean: Whether to pull revokation statuses from a remote server. (Default: true)
        */

        if (!chain || typeof chain !== 'string') throw new TypeError("Chain must be a string.");
        if (checkRevoked !== false) checkRevoked = true;

        chain = _load(chain);
        const now = Date.now();
        isChainValid = true;

        // Check certificates are all valid.
        for (let i = 0;chain.length > i;i++) {
            try {
                let cert = chain[i];
                let notBefore = new Date(cert.notBefore).getTime();
                let notAfter = new Date(cert.notAfter).getTime();
                let hash = _hash(Forge.pki.certificateToPem(cert));
                let basicConstraints = cert.extensions.find(v => v.name === "basicConstraints");

                // Check the certificate isn't expired...
                if (notAfter - now < 0) throw new Error("A certificate in the chain has expired.");

                // If the certificate is an issuer...
                if (i !== 0) {
                    // Check the certificate is an authorised CA.
                    if (!basicConstraints.cA) throw new Error("An issuing certificate has not been authorised as a certificate authority, but has attempted to act as one.");

                    // If the issuer authorized a CA...
                    if (chain[i - 2]) {
                        let chainLength = 0;
                        let past = false;

                        // If there is a path length constraint...
                        let pathLenConstraint = basicConstraints.pathLenConstraint;
                        if (pathLenConstraint) {
                            // Check that the issuer can issue further certificates.
                            if (pathLenConstraint < 0) throw new Error("An issuing certificate has authorized further certificate authorities whilst being disallowed from doing so.");

                            // Go through the certification path...
                            for (let ii = chain.length;ii > 0;ii--) {
                                let belowCert = chain[ii];
                                if (belowCert === cert) {
                                    past = true;
                                    continue;
                                }

                                if (!past) continue;

                                let belowBasicConstraints = belowCert.extensions.find(v => v.name === "basicConstraints");
                                if (belowBasicConstraints.cA) chainLength++;
                            }

                            // Make sure the certification path isn't too long.
                            if (chainLength > pathLenConstraint) throw new Error("An issuing certificate's chain is too long.");
                        }
                    }

                    // If the issuer isn't root...
                    if (i < chain.length - 1) {
                        let issuer = chain[i + 1];

                        // Check that is was signed by it's issuer.
                        try {
                            if (!issuer.verify(cert)) throw new Error();
                        } catch (err) {
                            throw new Error("An issuing certificate was not signed by it's apparent issuer.");
                        }

                        // Check that it was signed after the issuer was authorized.
                        if (notBefore - new Date(issuer.notBefore).getTime() < 0) throw new Error("An issuer's certificate was authorized before it's issuer was.");
                    }

                    // If the issuer is root...
                    if (i === chain.length - 1) {
                        // Check it is actually the OpenSend root.
                        let knownRoot = Forge.pki.certificateFromPem(ROOT());
                        if (Forge.pki.certificateToPem(cert) !== Forge.pki.certificateToPem(knownRoot)) throw new Error("The provided root certificate does not match the OpenSend Authoritative Root CA.")

                        // Check it was issued by itself.
                        try {
                            if (!knownRoot.verify(cert)) throw new Error();
                        } catch (err) {
                            throw new Error("The root certificate was not issued to itself.");
                        }
                    }

                    // If the certificate is an authoritative intermediate...
                    if (cert.subject.attributes.find(v => v.name === "commonName").value.includes("Authoritative Intermediate")) {
                        // Check that it's in the right position.
                        if (i !== chain.length - 2) throw new Error("A certificate incorrectly identifies itself as an authoritative intermediate.");

                        // Check it's the right authoritative intermediate.
                        if (!cert.subject.attributes.find(v => v.name === "commonName").value.startsWith("OpenSend Relay Authentication")) throw new Error("A certificate has been used incorrectly.");
                    }
                } else { // If the certificate is the end entity...
                    // Check it was signed by it's issuer.
                    try {
                        if (!chain[1].verify(cert)) throw new Error();
                    } catch (err) {
                        throw new Error("The end entity certificate was not signed by it's issuer.");
                    }
                }

                // Finally, check the certificate isn't revoked:
                let valid = true;
                if (checkRevoked) {
                    valid = await new Promise((resolve) => {
                        fetch("https://ca.opensend.net/relays/" + hash + ".json").then(x => x.json()).then((res) => {
                            if (!res.exists || res.revoked) resolve(false);
                            resolve(true);
                        }).catch((err) => {
                            console.error(err);
                            resolve(false)
                        });
                    });
                }

                if (!valid) isChainValid = false;
            } catch (err) {
                console.error("Error:");
                throw err;
            }
        }

        return isChainValid;
    },
    p2p: async (chain, checkRevoked) => {
        /*
            * <b>chain</b> string: The full certificate chain.<br>
            * <b>checkRevoked</b>? boolean: Whether to pull revokation statuses from a remote server. (Default: true)
        */

        if (!chain || typeof chain !== 'string') throw new TypeError("Chain must be a string.");
        if (checkRevoked !== false) checkRevoked = true;

        chain = _load(chain);
        const now = Date.now();
        isChainValid = true;

        // Check certificates are all valid.
        for (let i = 0;chain.length > i;i++) {
            try {
                let cert = chain[i];
                let notBefore = new Date(cert.notBefore).getTime();
                let notAfter = new Date(cert.notAfter).getTime();
                let hash = _hash(Forge.pki.certificateToPem(cert));
                let basicConstraints = cert.extensions.find(v => v.name === "basicConstraints");

                // Check the certificate isn't expired...
                if (notAfter - now < 0) throw new Error("A certificate in the chain has expired.");

                // If the certificate is an issuer...
                if (i !== 0) {
                    // Check the certificate is an authorised CA.
                    if (!basicConstraints.cA) throw new Error("An issuing certificate has not been authorised as a certificate authority, but has attempted to act as one.");

                    // If the issuer authorized a CA...
                    if (chain[i - 2]) {
                        let chainLength = 0;
                        let past = false;

                        // If there is a path length constraint...
                        let pathLenConstraint = basicConstraints.pathLenConstraint;
                        if (pathLenConstraint) {
                            // Check that the issuer can issue further certificates.
                            if (pathLenConstraint < 0) throw new Error("An issuing certificate has authorized further certificate authorities whilst being disallowed from doing so.");

                            // Go through the certification path...
                            for (let ii = chain.length;ii > 0;ii--) {
                                let belowCert = chain[ii];
                                if (belowCert === cert) {
                                    past = true;
                                    continue;
                                }

                                if (!past) continue;

                                let belowBasicConstraints = belowCert.extensions.find(v => v.name === "basicConstraints");
                                if (belowBasicConstraints.cA) chainLength++;
                            }

                            // Make sure the certification path isn't too long.
                            if (chainLength > pathLenConstraint) throw new Error("An issuing certificate's chain is too long.");
                        }
                    }

                    // If the issuer isn't root...
                    if (i < chain.length - 1) {
                        let issuer = chain[i + 1];

                        // Check that is was signed by it's issuer.
                        try {
                            if (!issuer.verify(cert)) throw new Error();
                        } catch (err) {
                            throw new Error("An issuing certificate was not signed by it's apparent issuer.");
                        }

                        // Check that it was signed after the issuer was authorized.
                        if (notBefore - new Date(issuer.notBefore).getTime() < 0) throw new Error("An issuer's certificate was authorized before it's issuer was.");
                    }

                    // If the issuer is root...
                    if (i === chain.length - 1) {
                        // Check it is actually the OpenSend root.
                        let knownRoot = Forge.pki.certificateFromPem(ROOT());
                        if (Forge.pki.certificateToPem(cert) !== Forge.pki.certificateToPem(knownRoot)) throw new Error("The provided root certificate does not match the OpenSend Authoritative Root CA.")

                        // Check it was issued by itself.
                        try {
                            if (!knownRoot.verify(cert)) throw new Error();
                        } catch (err) {
                            throw new Error("The root certificate was not issued to itself.");
                        }
                    }

                    // If the certificate is an authoritative intermediate...
                    if (cert.subject.attributes.find(v => v.name === "commonName").value.includes("Authoritative Intermediate")) {
                        // Check that it's in the right position.
                        if (i !== chain.length - 2) throw new Error("A certificate incorrectly identifies itself as an authoritative intermediate.");

                        // Check it's the right authoritative intermediate.
                        if (!cert.subject.attributes.find(v => v.name === "commonName").value.startsWith("OpenSend P2P Authentication")) throw new Error("A certificate has been used incorrectly.");
                    }
                } else { // If the certificate is the end entity...
                    // Check it was signed by it's issuer.
                    try {
                        if (!chain[1].verify(cert)) throw new Error();
                    } catch (err) {
                        throw new Error("The end entity certificate was not signed by it's issuer.");
                    }
                }

                // Finally, check the certificate isn't revoked:
                let valid = true;
                if (checkRevoked) {
                    valid = await new Promise((resolve) => {
                        fetch("https://ca.opensend.net/p2p/" + hash + ".json").then(x => x.json()).then((res) => {
                            if (!res.exists || res.revoked) resolve(false);
                            resolve(true);
                        }).catch((err) => {
                            console.error(err);
                            resolve(false)
                        });
                    });
                }

                if (!valid) isChainValid = false;
            } catch (err) {
                isChainValid = false;
            }
        }

        return isChainValid;
    }
};

function _hash (string) {
    let md = Forge.md.sha512.create();
    md.update(string);
    return md.digest().toHex();
}

function _load (chain) {
    chain = Split(chain);
    if (!chain || chain.length < 2) throw new Error("Certificate chain is invalid.");

    // Load all certificates
    let certificates = [];
    for (let i = 0;chain.length > i;i++) {
        try {
            let cert = Forge.pki.certificateFromPem(chain[i]);
            certificates.push(cert);
        } catch (err) {
            throw new Error("Failed to load certificates in chain. (Are they valid?)");
        }
    }

    return certificates;
}


//  ------- ROOT -------
function ROOT () {
    return "-----BEGIN CERTIFICATE-----\n" +
        "MIIJ3TCCBcWgAwIBAgIUTulWFPU6MB2R69/lJyVYXInVa5IwDQYJKoZIhvcNAQEL\n" +
        "BQAwdjELMAkGA1UEBhMCR0IxHjAcBgNVBAoMFU9wZW5TZW5kIFRlY2hub2xvZ2ll\n" +
        "czEnMCUGA1UEAwweT3BlblNlbmQgQXV0aG9yaXRhdGl2ZSBSb290IENBMR4wHAYJ\n" +
        "KoZIhvcNAQkBFg9jYUBvcGVuc2VuZC5uZXQwHhcNMjEwMzExMDIxMTM4WhcNNDYw\n" +
        "MzA1MDIxMTM4WjB2MQswCQYDVQQGEwJHQjEeMBwGA1UECgwVT3BlblNlbmQgVGVj\n" +
        "aG5vbG9naWVzMScwJQYDVQQDDB5PcGVuU2VuZCBBdXRob3JpdGF0aXZlIFJvb3Qg\n" +
        "Q0ExHjAcBgkqhkiG9w0BCQEWD2NhQG9wZW5zZW5kLm5ldDCCBCIwDQYJKoZIhvcN\n" +
        "AQEBBQADggQPADCCBAoCggQBANclIbBnrqklG+IpzEBIyPbuCiiDa62x1zdXaknh\n" +
        "i0nfx9fkFWqK1vyizpCbeoVRN2b65PaUL9rz+n461Cbq2CuOIZxKYJrxqOqpwrrt\n" +
        "ZvlvhYH3ZLsQfJZ1Lhjn1n2mzdpoPzAMi7g7t5Ny8Px9UfUwYTn0iBNPqGKjI1uA\n" +
        "6WT9EWhpzo2MiyyMmiJnP4msT5YBYr815NORru/q2dN9quqzzDvRx+Ax/VvWxT+V\n" +
        "s8fnv+TKEyQUDD2NGxMvJ27BZ8vO8ArpDbbEydg/g15dogZ25N2CsuHjWraPbPYl\n" +
        "/skp2tjHeL0Ge3vK0kA8n+46rfr+xxP10CZA8+WvMwFyFHjvVzy9YQFRHTelHl92\n" +
        "ZBnuCc81W2hUShhL+19H5ra/xbzlZvB78Qq5i86ClgRacV8jCcBLJKOqRbo5pb3O\n" +
        "ch+RvTsS2T/m77JUUACA9nkMWjW4qQUq+Mk+X0dR0k6+opTrhvTs9EtHtbYxskuq\n" +
        "d686FkjPk8Pl5L/OxewEsNFp3fBlp4Cm7IMzupLgFpx1ZErEoP0Wg250U8B8eYV7\n" +
        "XgShnCVfkIurDCmM7QfoAFkOR7xSMW+juCkqQT9slPKt/jzy8V9a8U9sYmI8rrQm\n" +
        "jMiNMkKpuClaVP+RMbicUTvXx0vQZLPcFoqY9bbWJ9QSZjNjh6fOfApIBu+cQ5Q6\n" +
        "4lLByeIPBAn/oXtYsAIGuEiW/QZSfdx3VleZezFipBsjk/nonmf7Z8ycSgBZrQJu\n" +
        "urxByTCbmn8bMoeZhwf/UlJqn6sDpS/366RRJ96n3x8LfL7oB2gjZLnclII6Ytq8\n" +
        "SLoFrCRHzPrpt2/nJmQIJlmAFHy5SkwWid4i1AuDitIIinT+1+84dmLrwUjRXRJ0\n" +
        "P7CaavLPVXS/pE1EZQlIpoRSpJcT9s+ne4mblMMV3OQh7EtETlWxGURHPucAAhOH\n" +
        "e6uduoWkszGtrkBVH+ohrcEKnh0BrmsAHlzMIRmTAU3n/B+Wfsf/bex1E9J9fu1v\n" +
        "9w7BXM9UDTV9v46QmOSvU1fWExZpKFr3E8IvZjQfwU147ljK4Q6bI0aAy68v47JD\n" +
        "HPz7JuCAZeHg/MbxhvLuBTnEzOi5qShOkGJ3GajAyIcHjC/a7n5Th0lV7n+IBhhS\n" +
        "HyaJT4Ihn1KSMBujhVR1gtvVYWPhv5TevnuC+a+SfME0IuzNE9DOTTuxjgjC9uEP\n" +
        "07mMdkJ3sr1k/jrmGmonJGGK5v775QFC7iEP2jC9dCpGyHCq7e4FSJb9EWOzhRUm\n" +
        "DPCAvwQJhDtFoI5i/tNI8svT8LNEr0o3lcsRJjYCqO2Yvf5mA80PFgv+cxJmBBEk\n" +
        "7neP9j5u29D2DNKMbt0TB/LZ5aiy8UG4FDIucyKRSrGSUjcCAwEAAaNjMGEwHQYD\n" +
        "VR0OBBYEFPmyDSK6SpbJ64pc3IwDXPXHrYuRMB8GA1UdIwQYMBaAFPmyDSK6SpbJ\n" +
        "64pc3IwDXPXHrYuRMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMA0G\n" +
        "CSqGSIb3DQEBCwUAA4IEAQC+akPavlgVZUeaJBd4/Wq3htOYeLPAyO1EiexppiT0\n" +
        "fVw9352d7t71SkxmEIGjZ4vpOnqXXqYXHJBFj1dFRu4l8b+i0UQs6bOM7Yk411bz\n" +
        "9iCUEzTQD1SLDB+EgddIeGssDUViuNbI2jD/u3Vv/9S/gSwW6bVP1ysPzNDjbETm\n" +
        "8cJGb+2Naz5LH0kkPyWh7zz81db0XEOCWJXePcI9ysSf0uJKPVDziO7Vj9yuNQLm\n" +
        "hH4SOcuFsMCWSqMpOR3D8j/0fLvQT17sgZv6BSyhIwFT5KPi+J/JCaMXs1DR0Hgm\n" +
        "FF6wy+xQQ6E6K9r8ZLAzu8xWIfenJod9V1wS/Srun4QWAqHaD5fyL1xbVoNGK69+\n" +
        "wOutZC/JehseadSWcI/VozoPoOLUPl371M+FJbRbS8BTsEH2fr+2rbL1SBASEXM9\n" +
        "VYaGu3DPMA0j4muO7tQvtU9ctW9GMnuBNqRBn+G0azWWt7RB58EOeJ9oZe0GQl3n\n" +
        "EPE9uxyCsncj8bo+IT9wt4oojqUGF/iiU84qfM6eX0nCfsa2hDJ01pf2d+QHi7jM\n" +
        "hrX6Y0R9evpHE277rpeuoI8XAUqvvmUxy5I5oqUgH99iJLVoSyiHsxXESgfTG51B\n" +
        "Y7/qyYK/U2gaLi13yl7+ds1sYCz1vYARW7keCtZUeqSMN/qgaANWqzmkH8G3Bk4F\n" +
        "UZtrCYTf9TsbNkLUI2IBye1I3QQK9XpGNUYUdcAV6vZGHwapPuSl+Oa7xs5y4Lfz\n" +
        "rtXZT7ciKWqSgRYXCbVNZ4MV91pEJYLteeqxsflZd//44//utAgy6bsc13qfBJHs\n" +
        "TpxZNRNvqSNvCbvQNqHvABsmLTqt/6WdRFzL/soW2BwlwbzzwdAWxnAHA05246Im\n" +
        "0raH6iSTLz8lnd643/IlG8aXEYk/kiZfPTo+G6S3Um0tdgis39yw8LmdLBsnGxwg\n" +
        "J7d0URVB7xfOzM2I83+jz46yI6wjpuobd+7l843vH1TIqMRRBWRj/eRXBUUhrVDi\n" +
        "JWca16LuueRycXMfwAHCwyIs5Sy9/Kz/ekzRMZ22Y9TBqZwjkafA3WSEpQVI7PYv\n" +
        "0PI1v/O/sZ/OLmlbc6P91qq/9j8G7BW6FZriRLGjlFxDnhPMEi7TYy7Wm6dLEe3Y\n" +
        "b9DvXHvVzDaATLYOQk4TjD5neS/pBssmup+PZpi8Cyav2pcNZ9+5QTsgYAarmti1\n" +
        "7hLWtz2T9jeow9qUufcYeHIXoCYMzHJ3TcpWBj+26T214MsaSjU8llgjnELXHu83\n" +
        "Hp7ngymiTQHyyYuE8ZMS0ROKe/JWzPv8yylKWdBKgoTOKgLq5wG03v3uE12r8xfa\n" +
        "RZMn2bantnvJa7MSYcWTpPOxWXXYZJwFi34tTNFhCx/V\n" +
        "-----END CERTIFICATE-----";
}


//  ------- SPLIT -------
/*

    This is a MODIFIED version of npm/split-ca.
    The following changes have been made:
        - Pass full chain instead of path to chain file.
        - Remove var usage.
        - Cleanup code.

    https://github.com/bushong1/split-ca
    https://npmjs.com/package/split-ca

    The original work was licensed under the ISC license:

    Permission to use, copy, modify, and/or distribute this software for any
    purpose with or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
    OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

 */

function Split (chain) {
    const ca = [];
    if(chain.indexOf("-END CERTIFICATE-") < 0 || chain.indexOf("-BEGIN CERTIFICATE-") < 0){
        throw new Error("Chain does not contain 'BEGIN CERTIFICATE' or 'END CERTIFICATE'");
    }
    chain = chain.split("\n");
    let cert = [];
    let _i, _len;
    for (_i = 0, _len = chain.length; _i < _len; _i++) {
        const line = chain[_i];
        if (!(line.length !== 0)) continue;
        cert.push(line);
        if (line.match(/-END CERTIFICATE-/)) {
            ca.push(cert.join("\n"));
            cert = [];
        }
    }
    return ca;
}
