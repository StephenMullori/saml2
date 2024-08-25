import { create } from "xmlbuilder2";

const xml = create({
  AuthnRequest: {
    "@xmlns": XMLNS.SAMLP,
    "@xmlns:saml": XMLNS.SAML,
    "@Version": "2.0",
    "@ID": id,
    "@IssueInstant": new Date().toISOString(),
    "@Destination": destination,
    "@AssertionConsumerServiceURL": assert_endpoint,
    "@ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    "@ForceAuthn": force_authn,
    "saml:Issuer": issuer,
    NameIDPolicy: {
      "@Format":
        nameid_format ||
        "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
      "@AllowCreate": "true",
    },
    RequestedAuthnContext: context_element,
  },
}).end();

console.log(xml);
