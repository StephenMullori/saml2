import _ from "underscore";
import async from "async";
import crypto from "crypto";
import debug from "debug";
import url from "url";
import util from "util";
import { create } from "xmlbuilder2";
import { SignedXml, xpath } from "xml-crypto";
import { DOMParser, XMLSerializer } from "@xmldom/xmldom";
import { decrypt } from "xml-encryption";
import zlib from "zlib";
import { ParsedUrlQuery } from "querystring";

const XMLNS = {
  SAML: "urn:oasis:names:tc:SAML:2.0:assertion",
  SAMLP: "urn:oasis:names:tc:SAML:2.0:protocol",
  MD: "urn:oasis:names:tc:SAML:2.0:metadata",
  DS: "http://www.w3.org/2000/09/xmldsig#",
  XENC: "http://www.w3.org/2001/04/xmlenc#",
  EXC_C14N: "http://www.w3.org/2001/10/xml-exc-c14n#",
};

class SAMLError extends Error {
  constructor(public message: string, public extra?: any) {
    super(message);
  }
}

interface AuthnRequestResult {
  id: string;
  xml: string;
}
// Creates an AuthnRequest and returns it as a string of xml along with the randomly generated ID for the created request.
function create_authn_request(
  issuer: string,
  assert_endpoint: string,
  destination: string,
  force_authn: boolean,
  context: any,
  nameid_format?: string
): AuthnRequestResult {
  const context_element = context
    ? {
        "saml:AuthnContextClassRef": context.class_refs,
        "@Comparison": context.comparison,
      }
    : undefined;

  const id = "_" + crypto.randomBytes(21).toString("hex");
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

  return { id, xml };
}

interface ServiceProviderOptions {
  entity_id: string;
  private_key: string;
  certificate: string;
  assert_endpoint: string;
  alt_private_keys?: string[];
  alt_certs?: string[];
  audience?: string;
  notbefore_skew?: number;
  // ... other options
}

class ServiceProvider {
  private entity_id: string;
  private private_key: string;
  private certificate: string;
  private assert_endpoint: string;
  private alt_private_keys: string[];
  private alt_certs: string[];
  private shared_options: any;

  constructor(options: ServiceProviderOptions) {
    this.entity_id = options.entity_id;
    this.private_key = options.private_key;
    this.certificate = options.certificate;
    this.assert_endpoint = options.assert_endpoint;
    this.alt_private_keys = options.alt_private_keys || [];
    this.alt_certs = options.alt_certs || [];

    options.audience = options.audience || this.entity_id;
    options.notbefore_skew = options.notbefore_skew || 1;

    this.shared_options = _.pick(
      options,
      "force_authn",
      "auth_context",
      "nameid_format",
      "sign_get_request",
      "allow_unencrypted_assertion",
      "audience",
      "notbefore_skew"
    );
  }

  create_login_request_url(
    identity_provider: IdentityProvider,
    options: any,
    cb: (err: Error | null, loginUrl?: string, id?: string) => void
  ): void {
    options = set_option_defaults(
      options,
      identity_provider.shared_options,
      this.shared_options
    );

    const { id, xml } = create_authn_request(
      this.entity_id,
      this.assert_endpoint,
      identity_provider.sso_login_url,
      options.force_authn,
      options.auth_context,
      options.nameid_format
    );
    zlib.deflateRaw(xml, (err, deflated) => {
      if (err) return cb(err);
      try {
        const uri = new URL(identity_provider.sso_login_url);
        let query: ParsedUrlQuery = {};
        if (options.sign_get_request) {
          query = sign_request(
            deflated.toString("base64"),
            this.private_key,
            options.relay_state
          );
        } else {
          query.SAMLRequest = deflated.toString("base64");
          if (options.relay_state) query.RelayState = options.relay_state;
        }
        uri.search = new URLSearchParams(query as any).toString();
        cb(null, uri.toString(), id);
      } catch (ex) {
        cb(ex as Error);
      }
    });
  }

  create_authn_request_xml(
    identity_provider: IdentityProvider,
    options: any
  ): string {
    options = set_option_defaults(
      options,
      identity_provider.shared_options,
      this.shared_options
    );

    const { id, xml } = create_authn_request(
      this.entity_id,
      this.assert_endpoint,
      identity_provider.sso_login_url,
      options.force_authn,
      options.auth_context,
      options.nameid_format
    );
    return sign_authn_request(xml, this.private_key, options);
  }

  redirect_assert(
    identity_provider: IdentityProvider,
    options: any,
    cb: (err: Error | null, response?: any) => void
  ): void {
    options = _.defaults(_.extend(options, { get_request: true }), {
      require_session_index: true,
    });
    options = set_option_defaults(
      options,
      identity_provider.shared_options,
      this.shared_options
    );
    this._assert(identity_provider, options, cb);
  }

  post_assert(
    identity_provider: IdentityProvider,
    options: any,
    cb: (err: Error | null, response?: any) => void
  ): void {
    options = _.defaults(_.extend(options, { get_request: false }), {
      require_session_index: true,
    });
    options = set_option_defaults(
      options,
      identity_provider.shared_options,
      this.shared_options
    );
    this._assert(identity_provider, options, cb);
  }

  private _assert(
    identity_provider: IdentityProvider,
    options: any,
    cb: (err: Error | null, response?: any) => void
  ): void {
    if (
      !options.request_body?.SAMLResponse &&
      !options.request_body?.SAMLRequest
    ) {
      return setImmediate(
        cb,
        new Error("Request body does not contain SAMLResponse or SAMLRequest.")
      );
    }

    if (!_.isNumber(options.notbefore_skew)) {
      return setImmediate(
        cb,
        new Error("Configuration error: `notbefore_skew` must be a number")
      );
    }

    let saml_response: Document | null = null;
    let response: any = {};

    async.waterfall(
      [
        (cb_wf: (err: Error | null, response_buffer?: Buffer) => void) => {
          const raw = Buffer.from(
            options.request_body.SAMLResponse ||
              options.request_body.SAMLRequest,
            "base64"
          );

          if (options.get_request) {
            return zlib.inflateRaw(raw, cb_wf);
          }
          setImmediate(cb_wf, null, raw);
        },
        (
          response_buffer: Buffer,
          cb_wf: (err: Error | null, result?: any) => void
        ) => {
          const saml_response_abnormalized = add_namespaces_to_child_assertions(
            response_buffer.toString()
          );
          saml_response = new DOMParser().parseFromString(
            saml_response_abnormalized
          );

          try {
            response = {
              response_header: parse_response_header(saml_response),
            };
          } catch (err) {
            return cb_wf(err as Error);
          }

          if (
            saml_response.getElementsByTagNameNS(XMLNS.SAMLP, "Response")
              .length === 1
          ) {
            if (!check_status_success(saml_response)) {
              return cb_wf(
                new SAMLError("SAML Response was not success!", {
                  status: get_status(saml_response),
                })
              );
            }

            response.type = "authn_response";

            parse_authn_response(
              saml_response,
              [this.private_key, ...this.alt_private_keys],
              identity_provider.certificates,
              options.allow_unencrypted_assertion,
              options.ignore_signature,
              options.require_session_index,
              options.ignore_timing,
              options.notbefore_skew,
              options.audience,
              cb_wf
            );
          } else if (
            saml_response.getElementsByTagNameNS(XMLNS.SAMLP, "LogoutResponse")
              .length === 1
          ) {
            if (!check_status_success(saml_response)) {
              return cb_wf(
                new SAMLError("SAML Response was not success!", {
                  status: get_status(saml_response),
                })
              );
            }

            response.type = "logout_response";
            setImmediate(cb_wf, null, {});
          } else if (
            saml_response.getElementsByTagNameNS(XMLNS.SAMLP, "LogoutRequest")
              .length === 1
          ) {
            response.type = "logout_request";
            setImmediate(cb_wf, null, parse_logout_request(saml_response));
          }
        },
        (result: any, cb_wf: (err: Error | null, response?: any) => void) => {
          _.extend(response, result);
          cb_wf(null, response);
        },
      ],
      cb
    );
  }
  create_logout_request_url(
    identity_provider: IdentityProvider | string,
    options: any,
    cb: (err: Error | null, logoutUrl?: string, id?: string) => void
  ): void {
    if (typeof identity_provider === "string") {
      identity_provider = {
        sso_logout_url: identity_provider,
        options: {},
      } as IdentityProvider;
    }
    options = set_option_defaults(
      options,
      identity_provider.shared_options,
      this.shared_options
    );
    const { id, xml } = create_logout_request(
      this.entity_id,
      options.name_id,
      options.session_index,
      identity_provider.sso_logout_url
    );
    zlib.deflateRaw(xml, (err, deflated) => {
      if (err) return cb(err);
      try {
        const uri = new URL(identity_provider.sso_logout_url);
        let query: any = {};
        if (options.sign_get_request) {
          query = sign_request(
            deflated.toString("base64"),
            this.private_key,
            options.relay_state
          );
        } else {
          query.SAMLRequest = deflated.toString("base64");
          if (options.relay_state) query.RelayState = options.relay_state;
        }
        uri.search = new URLSearchParams(query).toString();
        cb(null, uri.toString(), id);
      } catch (ex) {
        cb(ex as Error);
      }
    });
  }

  create_logout_response_url(
    identity_provider: IdentityProvider | string,
    options: any,
    cb: (err: Error | null, logoutUrl?: string) => void
  ): void {
    if (typeof identity_provider === "string") {
      identity_provider = {
        sso_logout_url: identity_provider,
        options: {},
      } as IdentityProvider;
    }
    options = set_option_defaults(
      options,
      identity_provider.shared_options,
      this.shared_options
    );

    const xml = create_logout_response(
      this.entity_id,
      options.in_response_to,
      identity_provider.sso_logout_url
    );
    zlib.deflateRaw(xml, (err, deflated) => {
      if (err) return cb(err);
      try {
        const uri = new URL(identity_provider.sso_logout_url);
        let query: any = {};
        if (options.sign_get_request) {
          query = sign_request(
            deflated.toString("base64"),
            this.private_key,
            options.relay_state,
            true
          );
        } else {
          query.SAMLResponse = deflated.toString("base64");
          if (options.relay_state) query.RelayState = options.relay_state;
        }
        uri.search = new URLSearchParams(query).toString();
        cb(null, uri.toString());
      } catch (ex) {
        cb(ex as Error);
      }
    });
  }

  create_metadata(): string {
    const certs = [this.certificate, ...this.alt_certs];
    return create_metadata(this.entity_id, this.assert_endpoint, certs, certs);
  }
}

interface IdentityProviderOptions {
  sso_login_url: string;
  sso_logout_url: string;
  certificates: string | string[];
  force_authn?: boolean;
  sign_get_request?: boolean;
  allow_unencrypted_assertion?: boolean;
  sign_metadata?: boolean;
  private_key?: string;
}

class IdentityProvider {
  public sso_login_url: string;
  public sso_logout_url: string;
  public certificates: string[];
  public shared_options: any;
  private sign_metadata: boolean;
  private private_key?: string;

  constructor(options: IdentityProviderOptions) {
    this.sso_login_url = options.sso_login_url;
    this.sso_logout_url = options.sso_logout_url;
    this.certificates = Array.isArray(options.certificates)
      ? options.certificates
      : [options.certificates];
    this.shared_options = _.pick(
      options,
      "force_authn",
      "sign_get_request",
      "allow_unencrypted_assertion"
    );
    this.sign_metadata = options.sign_metadata || false;
    this.private_key = options.private_key;
  }

  create_metadata(
    entity_id: string,
    assertion_consumer_service_url: string
  ): string {
    const metadata = create({
      "md:EntityDescriptor": {
        "@xmlns:md": XMLNS.MD,
        "@xmlns:ds": XMLNS.DS,
        "@entityID": entity_id,
        "md:IDPSSODescriptor": {
          "@protocolSupportEnumeration": "urn:oasis:names:tc:SAML:2.0:protocol",
          "md:KeyDescriptor": this.certificates.map((cert) => ({
            "@use": "signing",
            "ds:KeyInfo": {
              "ds:X509Data": {
                "ds:X509Certificate": cert
                  .replace(/-----BEGIN CERTIFICATE-----/, "")
                  .replace(/-----END CERTIFICATE-----/, "")
                  .replace(/\n/g, ""),
              },
            },
          })),
          "md:NameIDFormat":
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
          "md:SingleSignOnService": {
            "@Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            "@Location": this.sso_login_url,
          },
          "md:SingleLogoutService": {
            "@Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            "@Location": this.sso_logout_url,
          },
        },
      },
    }).end();

    if (this.sign_metadata && this.private_key) {
      // Here you would implement the logic to sign the metadata
      // This is a complex process and depends on how you want to sign it
      return this.sign_metadata_xml(metadata);
    }

    return metadata;
  }

  private sign_metadata_xml(metadata: string): string {
    // Implement metadata signing logic here
    // This is a placeholder and should be replaced with actual signing logic
    console.warn("Metadata signing is not implemented");
    return metadata;
  }

  validate_response(response: string): boolean {
    // Implement SAML response validation logic here
    // This is a placeholder and should be replaced with actual validation logic
    console.warn("Response validation is not implemented");
    return true;
  }

  generate_login_request(sp_entity_id: string, acs_url: string): string {
    const request_id = "_" + Math.random().toString(36).substr(2, 9);
    const issue_instant = new Date().toISOString();

    return create({
      "samlp:AuthnRequest": {
        "@xmlns:samlp": XMLNS.SAMLP,
        "@xmlns:saml": XMLNS.SAML,
        "@ID": request_id,
        "@Version": "2.0",
        "@IssueInstant": issue_instant,
        "@Destination": this.sso_login_url,
        "@AssertionConsumerServiceURL": acs_url,
        "@ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        "saml:Issuer": sp_entity_id,
        "samlp:NameIDPolicy": {
          "@Format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
          "@AllowCreate": "true",
        },
      },
    }).end();
  }

  generate_logout_request(
    name_id: string,
    session_index: string,
    sp_entity_id: string
  ): string {
    const request_id = "_" + Math.random().toString(36).substr(2, 9);
    const issue_instant = new Date().toISOString();

    return create({
      "samlp:LogoutRequest": {
        "@xmlns:samlp": XMLNS.SAMLP,
        "@xmlns:saml": XMLNS.SAML,
        "@ID": request_id,
        "@Version": "2.0",
        "@IssueInstant": issue_instant,
        "@Destination": this.sso_logout_url,
        "saml:Issuer": sp_entity_id,
        "saml:NameID": name_id,
        "samlp:SessionIndex": session_index,
      },
    }).end();
  }
}

function set_option_defaults(
  request_options: any,
  idp_options: any,
  sp_options: any
): any {
  return _.defaults({}, request_options, idp_options, sp_options);
}

// Helper functions

function create_logout_request(
  entity_id: string,
  name_id: string,
  session_index: string,
  destination: string
): { id: string; xml: string } {
  const id = "_" + crypto.randomBytes(21).toString("hex");
  const xml = create({
    "samlp:LogoutRequest": {
      "@xmlns:samlp": XMLNS.SAMLP,
      "@xmlns:saml": XMLNS.SAML,
      "@ID": id,
      "@Version": "2.0",
      "@IssueInstant": new Date().toISOString(),
      "@Destination": destination,
      "saml:Issuer": entity_id,
      "saml:NameID": name_id,
      "samlp:SessionIndex": session_index,
    },
  }).end();

  return { id, xml };
}

function create_logout_response(
  entity_id: string,
  in_response_to: string,
  destination: string,
  status: string = "urn:oasis:names:tc:SAML:2.0:status:Success"
): string {
  return create({
    "samlp:LogoutResponse": {
      "@Destination": destination,
      "@ID": "_" + crypto.randomBytes(21).toString("hex"),
      "@InResponseTo": in_response_to,
      "@IssueInstant": new Date().toISOString(),
      "@Version": "2.0",
      "@xmlns:samlp": XMLNS.SAMLP,
      "@xmlns:saml": XMLNS.SAML,
      "saml:Issuer": entity_id,
      "samlp:Status": {
        "samlp:StatusCode": {
          "@Value": status,
        },
      },
    },
  }).end();
}

function sign_request(
  saml_request: string,
  private_key: string,
  relay_state?: string,
  response: boolean = false
): any {
  const action = response ? "SAMLResponse" : "SAMLRequest";
  const saml_request_data = `${action}=${encodeURIComponent(saml_request)}`;
  const relay_state_data = relay_state
    ? `&RelayState=${encodeURIComponent(relay_state)}`
    : "";
  const sigalg_data = `&SigAlg=${encodeURIComponent(
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
  )}`;

  const sign = crypto.createSign("RSA-SHA256");
  sign.update(saml_request_data + relay_state_data + sigalg_data);

  const samlQueryString: any = {};

  if (response) {
    samlQueryString.SAMLResponse = saml_request;
  } else {
    samlQueryString.SAMLRequest = saml_request;
  }

  if (relay_state) {
    samlQueryString.RelayState = relay_state;
  }

  samlQueryString.SigAlg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  samlQueryString.Signature = sign.sign(
    format_pem(private_key, "PRIVATE KEY"),
    "base64"
  );

  return samlQueryString;
}

function create_metadata(
  entity_id: string,
  assert_endpoint: string,
  signing_certificates: string[],
  encryption_certificates: string[]
): string {
  const signing_cert_descriptors = signing_certificates.map((cert) =>
    certificate_to_keyinfo("signing", cert)
  );

  const encryption_cert_descriptors = encryption_certificates.map((cert) =>
    certificate_to_keyinfo("encryption", cert)
  );

  return create({
    "md:EntityDescriptor": {
      "@xmlns:md": XMLNS.MD,
      "@xmlns:ds": XMLNS.DS,
      "@entityID": entity_id,
      "@validUntil": new Date(Date.now() + 1000 * 60 * 60).toISOString(),
      "md:SPSSODescriptor": {
        "@protocolSupportEnumeration":
          "urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol",
        "md:KeyDescriptor": [
          ...signing_cert_descriptors,
          ...encryption_cert_descriptors,
        ],
        "md:SingleLogoutService": {
          "@Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
          "@Location": assert_endpoint,
        },
        "md:AssertionConsumerService": {
          "@Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          "@Location": assert_endpoint,
          "@index": "0",
        },
      },
    },
  }).end();
}

//  Creates an AuthnRequest and returns it as a string of xml along with the randomly generated ID for the created request.
function signAuthnRequest(
  xml: string,
  privateKey: string,
  options?: any
): string {
  const signer = new SignedXml(null, options);
  signer.addReference("//*[local-name(.)='AuthnRequest']", [
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
    "http://www.w3.org/2001/10/xml-exc-c14n#",
  ]);
  signer.signingKey = privateKey;
  signer.computeSignature(xml);
  return signer.getSignedXml();
}

// This checks the signature of a saml document and returns either array containing the signed data if valid, or null if the signature is invalid. Comparing the result against null is NOT sufficient for signature checks as it doesn't verify the signature is signing the important content, nor is it preventing the parsing of unsigned content.
function check_saml_signature(
  xml: string,
  certificate: string
): string[] | null {
  const doc = new DOMParser().parseFromString(xml);

  // xpath failed to capture <ds:Signature> nodes of direct descendents of the root. Call documentElement to explicitly start from the root element of the document.
  const signature = xpath(
    doc.documentElement,
    "./*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']"
  );
  if (signature.length !== 1) return null;

  const sig = new SignedXml();
  sig.keyInfoProvider = {
    getKey: () => format_pem(certificate, "CERTIFICATE"),
  };

  sig.loadSignature(signature[0]);
  const valid = sig.checkSignature(xml);

  if (valid) {
    return get_signed_data(doc, sig);
  } else {
    return null;
  }
}
// Takes in an xml @dom containing a SAML Status and returns true if at least one status is Success.
function check_status_success(dom: Document): boolean {
  const status = dom.getElementsByTagNameNS(XMLNS.SAMLP, "Status");
  if (status.length !== 1) return false;

  for (let i = 0; i < status[0].childNodes.length; i++) {
    const statusCode = status[0].childNodes[i] as Element;
    if (statusCode.attributes) {
      const statusValue = get_attribute_value(statusCode, "Value");
      if (statusValue === "urn:oasis:names:tc:SAML:2.0:status:Success") {
        return true;
      }
    }
  }
  return false;
}

function pretty_assertion_attributes(
  assertion_attributes: Record<string, string[]>
): Record<string, string> {
  const claim_map: Record<string, string> = {
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":
      "email",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname":
      "given_name",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": "name",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": "upn",
    "http://schemas.xmlsoap.org/claims/CommonName": "common_name",
    "http://schemas.xmlsoap.org/claims/Group": "group",
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "role",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": "surname",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier":
      "ppid",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier":
      "name_id",
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod":
      "authentication_method",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/denyonlysid":
      "deny_only_group_sid",
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarysid":
      "deny_only_primary_sid",
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarygroupsid":
      "deny_only_primary_group_sid",
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid":
      "group_sid",
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarygroupsid":
      "primary_group_sid",
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid":
      "primary_sid",
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname":
      "windows_account_name",
  };

  return _.chain(assertion_attributes)
    .pairs()
    .filter(([k, v]) => claim_map[k] && v.length > 0)
    .map(([k, v]) => [claim_map[k], v[0]])
    .object()
    .value();
}

function decrypt_assertion(
  dom: Document,
  private_keys: string[],
  cb: (err: Error | null, result?: string) => void
): void {
  const cb_wrapped = _.wrap(
    cb,
    (fn: Function, err: Error | null, ...args: any[]) => {
      setTimeout(() => fn(to_error(err), ...args), 0);
    }
  );

  try {
    const encrypted_assertion = dom.getElementsByTagNameNS(
      XMLNS.SAML,
      "EncryptedAssertion"
    );
    if (encrypted_assertion.length !== 1) {
      return cb_wrapped(
        new Error(
          `Expected 1 EncryptedAssertion; found ${encrypted_assertion.length}.`
        )
      );
    }

    const encrypted_data = encrypted_assertion[0].getElementsByTagNameNS(
      XMLNS.XENC,
      "EncryptedData"
    );
    if (encrypted_data.length !== 1) {
      return cb_wrapped(
        new Error(
          `Expected 1 EncryptedData inside EncryptedAssertion; found ${encrypted_data.length}.`
        )
      );
    }

    const encrypted_assertion_string = encrypted_assertion[0].toString();
    const errors: Error[] = [];

    async.eachOfSeries(
      private_keys,
      (private_key, index, cb_e) => {
        decrypt(
          encrypted_assertion_string,
          { key: format_pem(private_key, "PRIVATE KEY") },
          (err, result) => {
            if (err) {
              errors.push(new Error(`Decrypt failed: ${util.inspect(err)}`));
              return cb_e();
            }

            console.log(`Decryption successful with private key #${index}.`);
            cb_wrapped(null, result);
          }
        );
      },
      () =>
        cb_wrapped(
          new Error(
            `Failed to decrypt assertion with provided key(s): ${util.inspect(
              errors
            )}`
          )
        )
    );
  } catch (err) {
    cb_wrapped(new Error(`Decrypt failed: ${util.inspect(err)}`));
  }
}
// Takes in an xml @dom of an object containing a SAML Response and returns an object containing the Destination and
// InResponseTo attributes of the Response if present. It will throw an error if the Response is missing or does not
// appear to be valid.
interface ResponseHeader {
  version: string;
  destination: string | null;
  in_response_to: string | null;
  id: string | null;
}

function parse_response_header(dom: Document): ResponseHeader {
  let response: Element | null = null;
  const responseTypes = ["Response", "LogoutResponse", "LogoutRequest"];

  for (const responseType of responseTypes) {
    const elements = dom.getElementsByTagNameNS(XMLNS.SAMLP, responseType);
    if (elements.length > 0) {
      response = elements[0];
      break;
    }
  }

  if (!response) {
    throw new Error(
      `Expected 1 Response, LogoutResponse, or LogoutRequest; found none`
    );
  }

  const responseHeader: ResponseHeader = {
    version: get_attribute_value(response, "Version") || "2.0",
    destination: get_attribute_value(response, "Destination"),
    in_response_to: get_attribute_value(response, "InResponseTo"),
    id: get_attribute_value(response, "ID"),
  };

  if (responseHeader.version !== "2.0") {
    throw new Error(`Invalid SAML Version ${responseHeader.version}`);
  }

  return responseHeader;
}

function get_attribute_value(
  element: Element,
  attributeName: string
): string | null {
  return element.getAttribute(attributeName);
}

interface LogoutRequest {
  issuer: string | null;
  name_id: string | null;
  session_index: string | null;
}

function parse_logout_request(dom: Document): LogoutRequest {
  const request = dom.getElementsByTagNameNS(XMLNS.SAMLP, "LogoutRequest");
  if (request.length !== 1) {
    throw new Error(`Expected 1 LogoutRequest; found ${request.length}`);
  }

  const result: LogoutRequest = {
    issuer: null,
    name_id: null,
    session_index: null,
  };

  // Parse Issuer
  const issuer = dom.getElementsByTagNameNS(XMLNS.SAML, "Issuer");
  if (issuer.length === 1 && issuer[0].firstChild) {
    result.issuer = issuer[0].firstChild.nodeValue;
  }

  // Parse NameID
  const name_id = dom.getElementsByTagNameNS(XMLNS.SAML, "NameID");
  if (name_id.length === 1 && name_id[0].firstChild) {
    result.name_id = name_id[0].firstChild.nodeValue;
  }

  // Parse SessionIndex
  const session_index = dom.getElementsByTagNameNS(XMLNS.SAMLP, "SessionIndex");
  if (session_index.length === 1 && session_index[0].firstChild) {
    result.session_index = session_index[0].firstChild.nodeValue;
  }

  return result;
}

function sign_authn_request(
  xml: string,
  private_key: string,
  options?: any
): string {
  const signer = new SignedXml(null, options);
  signer.addReference("//*[local-name(.)='AuthnRequest']", [
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
    "http://www.w3.org/2001/10/xml-exc-c14n#",
  ]);
  signer.signingKey = private_key;
  signer.computeSignature(xml);
  return signer.getSignedXml();
}

// Takes a base64 encoded @key and returns it formatted with newlines and a PEM header according to @type. If it already has a PEM header, it will just return the original key.
function format_pem(key: string, type: string): string {
  if (/-----BEGIN [0-9A-Z ]+-----[^-]*-----END [0-9A-Z ]+-----/g.exec(key)) {
    return key;
  }
  const matches = key.match(/.{1,64}/g);
  if (!matches) {
    throw new Error("Invalid key format");
  }
  return `-----BEGIN ${type.toUpperCase()}-----\n${matches.join(
    "\n"
  )}\n-----END ${type.toUpperCase()}-----`;
}

function get_name_id(dom: Document): string | null {
  const assertion = dom.getElementsByTagNameNS(XMLNS.SAML, "Assertion");
  if (assertion.length !== 1) {
    throw new Error(`Expected 1 Assertion; found ${assertion.length}`);
  }

  const subject = assertion[0].getElementsByTagNameNS(XMLNS.SAML, "Subject");
  if (subject.length !== 1) {
    throw new Error(`Expected 1 Subject; found ${subject.length}`);
  }

  const nameId = subject[0].getElementsByTagNameNS(XMLNS.SAML, "NameID");
  if (nameId.length !== 1) {
    return null;
  }

  return nameId[0].firstChild?.textContent || null;
}

interface SessionInfo {
  index: string | null;
  not_on_or_after: string | null;
}

function get_session_info(
  dom: Document,
  index_required: boolean = true
): SessionInfo {
  const assertion = dom.getElementsByTagNameNS(XMLNS.SAML, "Assertion");
  if (assertion.length !== 1) {
    throw new Error(`Expected 1 Assertion; found ${assertion.length}`);
  }

  const authnStatement = assertion[0].getElementsByTagNameNS(
    XMLNS.SAML,
    "AuthnStatement"
  );
  if (authnStatement.length !== 1) {
    throw new Error(
      `Expected 1 AuthnStatement; found ${authnStatement.length}`
    );
  }

  const info: SessionInfo = {
    index: authnStatement[0].getAttribute("SessionIndex"),
    not_on_or_after: authnStatement[0].getAttribute("SessionNotOnOrAfter"),
  };

  if (index_required && !info.index) {
    throw new Error("SessionIndex not an attribute of AuthnStatement.");
  }

  return info;
}

function to_error(err: any): Error | null {
  if (!err) return null;
  if (err instanceof Error) return err;
  return new Error(JSON.stringify(err));
}

function parse_assertion_attributes(dom: Document): Record<string, string[]> {
  const assertion = dom.getElementsByTagNameNS(XMLNS.SAML, "Assertion");
  if (assertion.length !== 1) {
    throw new Error(`Expected 1 Assertion; found ${assertion.length}`);
  }

  const attributeStatement = assertion[0].getElementsByTagNameNS(
    XMLNS.SAML,
    "AttributeStatement"
  );
  if (attributeStatement.length > 1) {
    throw new Error(
      `Expected 0 or 1 AttributeStatement inside Assertion; found ${attributeStatement.length}`
    );
  }
  if (attributeStatement.length === 0) {
    return {};
  }

  const assertionAttributes: Record<string, string[]> = {};
  const attributes = attributeStatement[0].getElementsByTagNameNS(
    XMLNS.SAML,
    "Attribute"
  );

  for (let i = 0; i < attributes.length; i++) {
    const attribute = attributes[i];
    const attributeName = attribute.getAttribute("Name");
    if (!attributeName) {
      throw new Error("Invalid attribute without name");
    }
    const attributeValues = attribute.getElementsByTagNameNS(
      XMLNS.SAML,
      "AttributeValue"
    );
    assertionAttributes[attributeName] = Array.from(attributeValues).map(
      (av) => av.textContent || ""
    );
  }

  return assertionAttributes;
}

function add_namespaces_to_child_assertions(xml_string: string): string {
  const doc = new DOMParser().parseFromString(xml_string, "text/xml");

  const responseElements = doc.getElementsByTagNameNS(XMLNS.SAMLP, "Response");
  if (responseElements.length !== 1) {
    return xml_string;
  }
  const responseElement = responseElements[0];

  const assertionElements = responseElement.getElementsByTagNameNS(
    XMLNS.SAML,
    "Assertion"
  );
  if (assertionElements.length !== 1) {
    return xml_string;
  }
  const assertionElement = assertionElements[0];

  const inclusiveNamespaces = assertionElement.getElementsByTagNameNS(
    XMLNS.EXC_C14N,
    "InclusiveNamespaces"
  )[0];
  let namespaces: string[] = [];

  if (inclusiveNamespaces) {
    const prefixList = inclusiveNamespaces.getAttribute("PrefixList");
    if (prefixList) {
      namespaces = prefixList
        .trim()
        .split(" ")
        .map((ns) => `xmlns:${ns}`);
    }
  } else {
    namespaces = Array.from(responseElement.attributes)
      .filter((attr) => attr.name.startsWith("xmlns:"))
      .map((attr) => attr.name);
  }

  // Add namespaces present in response and missing in assertion
  namespaces.forEach((ns) => {
    if (
      responseElement.hasAttribute(ns) &&
      !assertionElement.hasAttribute(ns)
    ) {
      const value = responseElement.getAttribute(ns);
      if (value) {
        assertionElement.setAttribute(ns, value);
      }
    }
  });

  return new XMLSerializer().serializeToString(responseElement);
}

function extract_certificate_data(certificate: string): string {
  const certData =
    /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(
      certificate
    );
  if (!certData) {
    throw new Error("Invalid Certificate");
  }

  return certData[1].replace(/[\r\n]/g, "");
}

export {
  ServiceProvider,
  IdentityProvider,
  create_authn_request,
  sign_authn_request,
  create_metadata,
  format_pem,
  sign_request,
  check_saml_signature,
  check_status_success,
  pretty_assertion_attributes,
  decrypt_assertion,
  parse_response_header,
  parse_logout_request,
  get_name_id,
  get_session_info,
  parse_assertion_attributes,
  add_namespaces_to_child_assertions,
  set_option_defaults,
  extract_certificate_data,
};
