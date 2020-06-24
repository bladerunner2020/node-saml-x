const debug = require('debug')('node-saml');
const zlib = require('zlib');
const xml2js = require('xml2js');
const xmlCrypto = require('xml-crypto');
const crypto = require('crypto');
const url = require('url');
const querystring = require('querystring');
const xmlbuilder = require('xmlbuilder');
const xmlenc = require('xml-encryption');
const xpath = xmlCrypto.xpath;
const InMemoryCacheProvider = require('./inmemory-cache-provider.js').CacheProvider;
const algorithms = require('./algorithms');
const { signAuthnRequestPost } = require('./saml-post-signing');
const { promisify } = require('util');

const {XMLParser} = require('./xml-parser');

class SAML {
  constructor(options = {}) {
    if (Object.prototype.hasOwnProperty.call(options, 'cert') && !options.cert) {
      throw new Error('Invalid property: cert must not be empty');
    }

    let authnContext = options.authnContext === undefined ? 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport' : options.authnContext;
    if (!Array.isArray(authnContext)) {
      authnContext = [authnContext];
    }
    const requestIdExpirationPeriodMs = options.requestIdExpirationPeriodMs || 28800000; // 8 hours

    this.options = {
      callbackUrl: options.callbackUrl,
      protocol: options.protocol,
      path: options.path || '/saml/consume',
      host: options.host || 'localhost',
      issuer: options.issuer || 'onelogin_saml',
      identifierFormat: options.identifierFormat === undefined ? 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' : options.identifierFormat,
      authnContext,
      acceptedClockSkewMs: options.acceptedClockSkewMs || 0, // default to no skew
      validateInResponseTo: options.validateInResponseTo || false,
      requestIdExpirationPeriodMs,
      cacheProvider: options.cacheProvider || new InMemoryCacheProvider({ keyExpirationPeriodMs: requestIdExpirationPeriodMs }),
      entryPoint: options.entryPoint,
      logoutUrl: options.logoutUrl || options.entryPoint || '', // Default to Entry Point
      signatureAlgorithm: options.signatureAlgorithm || 'sha1', // sha1, sha256, or sha512
      /**
      * List of possible values for RACComparison:
      * - exact : Assertion context must exactly match a context in the list
      * - minimum:  Assertion context must be at least as strong as a context in the list
      * - maximum:  Assertion context must be no stronger than a context in the list
      * - better:  Assertion context must be stronger than all contexts in the list
      */
      RACComparison: ['exact', 'minimum', 'maximum', 'better'].includes(options.RACComparison) ? options.RACComparison : 'exact',

      // options without defaults
      audience: options.audience,
      cert: options.cert,
      privateCert: options.privateCert,
      decryptionPvk: options.decryptionPvk,
      digestAlgorithm: options.digestAlgorithm,
      xmlSignatureTransforms: options.xmlSignatureTransforms,
      additionalParams: options.additionalParams,
      additionalAuthorizeParams: options.additionalAuthorizeParams,
      attributeConsumingServiceIndex: options.attributeConsumingServiceIndex,
      disableRequestedAuthnContext: options.disableRequestedAuthnContext,
      forceAuthn: options.forceAuthn,
      providerName: options.providerName,
      disableRequestACSUrl: options.disableRequestACSUrl,
      idpIssuer: options.idpIssuer,
      additionalLogoutParams: options.additionalLogoutParams,
      logoutCallbackUrl: options.logoutCallbackUrl,
      passive: options.passive
    };

    this.cacheProvider = this.options.cacheProvider;
  }

  getAuthorizeUrl(req, options, callback) {
    return this._generateAuthorizeRequest(req, this.options.passive, false)
      .then((request) => {
        const operation = 'authorize';
        const overrideParams = options ? options.additionalParams || {} : {};
        return this._requestToUrl(request, null, operation, this._getAdditionalParams(req, operation, overrideParams), callback);
      })
      .catch(callback);
  }

  getAuthorizeForm(req, callback) {
    // The quoteattr() function is used in a context, where the result will not be evaluated by javascript
    // but must be interpreted by an XML or HTML parser, and it must absolutely avoid breaking the syntax
    // of an element attribute.
    const quoteattr = (s, preserveCR) => {
      preserveCR = preserveCR ? '&#13;' : '\n';
      return (`${s}`) // Forces the conversion to string.
        .replace(/&/g, '&amp;') // This MUST be the 1st replacement.
        .replace(/'/g, '&apos;') // The 4 other predefined entities, required.
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        // Add other replacements here for HTML only
        // Or for XML, only if the named entities are defined in its DTD.
        .replace(/\r\n/g, preserveCR) // Must be before the next replacement.
        .replace(/[\r\n]/g, preserveCR);
    };

    const getAuthorizeFormHelper = (err, buffer) => {
      if (err) {
        return callback(err);
      }

      const operation = 'authorize';
      const additionalParameters = this._getAdditionalParams(req, operation);
      const samlMessage = {
        SAMLRequest: buffer.toString('base64')
      };

      Object.keys(additionalParameters).forEach(k => {
        samlMessage[k] = additionalParameters[k] || '';
      });

      const formInputs = Object.keys(samlMessage).map(k => `<input type="hidden" name="${k}" value="${quoteattr(samlMessage[k])}" />`).join('\r\n');

      callback(null, [
        '<!DOCTYPE html>',
        '<html>',
        '<head>',
        '<meta charset="utf-8">',
        '<meta http-equiv="x-ua-compatible" content="ie=edge">',
        '</head>',
        '<body onload="document.forms[0].submit()">',
        '<noscript>',
        '<p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below once to proceed.</p>',
        '</noscript>',
        `<form method="post" action="${encodeURI(this.options.entryPoint)}">`,
        formInputs,
        '<input type="submit" value="Submit" />',
        '</form>',
        '<script>document.forms[0].style.display="none";</script>', // Hide the form if JavaScript is enabled
        '</body>',
        '</html>'
      ].join('\r\n'));
    };


    return this._generateAuthorizeRequest(req, this.options.passive, true)
      .then((request) => {
        if (this.options.skipRequestCompression) {
          getAuthorizeFormHelper(null, Buffer.from(request, 'utf8'));
        } else {
          zlib.deflateRaw(request, getAuthorizeFormHelper);
        }
      })
      .catch(callback);
  }

  getLogoutUrl(req, options, callback) {
    return this._generateLogoutRequest(req)
      .then(request => {
        const operation = 'logout';
        const overrideParams = options ? options.additionalParams || {} : {};
        return this._requestToUrl(request, null, operation, this._getAdditionalParams(req, operation, overrideParams), callback);
      });
  }

  getLogoutResponseUrl(req, {additionalParams = {}} = {}, callback) {
    const response = this._generateLogoutResponse(req, req.samlLogoutRequest);
    const operation = 'logout';
    const overrideParams = additionalParams;
    this._requestToUrl(null, response, operation, this._getAdditionalParams(req, operation, overrideParams), callback);
  }

  validatePostResponse({ SAMLResponse }, callback) {
    let inResponseTo;

    (async () => {
      const xml = Buffer.from(SAMLResponse, 'base64').toString('utf8');

      const certs = (await this._certsToCheck()).map(cert => this._certToPEM(cert));

      const xmlParser = new XMLParser(xml, {signaturePublicKeys: certs});

      const doc = xmlParser.parsedXml;

      if (!Object.prototype.hasOwnProperty.call(doc, 'documentElement')) {
        throw new Error('SAMLResponse is not valid base64-encoded XML');
      }
      inResponseTo = xmlParser.query('/saml2p:Response')[0].getAttribute('InResponseTo');

      await this._validateInResponseTo(inResponseTo);

      // Check if this document has a valid top-level signature
      const validSignature = xmlParser.signatureVerified;

      const assertionsQuery = '/saml2p:Response/claim:Assertion';
      const assertions = xmlParser.query(assertionsQuery);
      const encryptedAssertions = xmlParser.query('/saml2p:Response/claim:EncryptedAssertion');

      if (assertions.length + encryptedAssertions.length > 1) {
        // There's no reason I know of that we want to handle multiple assertions, and it seems like a
        //   potential risk vector for signature scope issues, so treat this as an invalid signature
        throw new Error('Invalid signature: multiple assertions');
      }

      if (assertions.length === 1) {
        const validAssertionSignature = xmlParser.verifySignature(certs, assertionsQuery);
        if (this.options.cert && !validSignature && !validAssertionSignature) {
          throw new Error('Invalid signature');
        }
        return this._processValidlySignedAssertion(assertions[0].toString(), xml, inResponseTo, callback);
      }

      if (encryptedAssertions.length === 1) {
        if (!this.options.decryptionPvk) { throw new Error('No decryption key for encrypted SAML response'); }

        const encryptedAssertionXml = encryptedAssertions[0].toString();

        const xmlencOptions = { key: this.options.decryptionPvk };
        const decryptFn = promisify(xmlenc.decrypt).bind(xmlenc);
        const decryptedXml = await decryptFn(encryptedAssertionXml, xmlencOptions);

        const decryptedXmlParser = new XMLParser(decryptedXml, {signaturePublicKeys: certs});

        const assertionsQuery = '/claim:Assertion';
        const decryptedAssertions = decryptedXmlParser.query(assertionsQuery);

        if (decryptedAssertions.length !== 1) {throw new Error('Invalid EncryptedAssertion content');}
        const validAssertionSignature = decryptedXmlParser.verifySignature(certs, assertionsQuery);

        if (this.options.cert && !validSignature && !validAssertionSignature) {
          throw new Error('Invalid signature from encrypted assertion');
        }

        return this._processValidlySignedAssertion(decryptedAssertions[0].toString(), xml, inResponseTo, callback);
      }

      // If there's no assertion, fall back on xml2js response parsing for the status & LogoutResponse code.

      const parserConfig = {
        explicitRoot: true,
        explicitCharkey: true,
        tagNameProcessors: [xml2js.processors.stripPrefix]
      };
      const parser = new xml2js.Parser(parserConfig);
      const doc2 = await parser.parseStringPromise(xml);
      const response = doc2.Response;
      if (response) {
        const assertion = response.Assertion;
        if (!assertion) {
          const status = response.Status;
          if (status) {
            const statusCode = status[0].StatusCode;
            if (statusCode && statusCode[0].$.Value === 'urn:oasis:names:tc:SAML:2.0:status:Responder') {
              const nestedStatusCode = statusCode[0].StatusCode;
              if (nestedStatusCode && nestedStatusCode[0].$.Value === 'urn:oasis:names:tc:SAML:2.0:status:NoPassive') {
                if (this.options.cert && !validSignature) {
                  throw new Error('Invalid signature: NoPassive');
                }
                return callback(null, null, false);
              }
            }

            // Note that we're not requiring a valid signature before this logic -- since we are
            //   throwing an error in any case, and some providers don't sign error results,
            //   let's go ahead and give the potentially more helpful error.
            if (statusCode && statusCode[0].$.Value) {
              const msgType = statusCode[0].$.Value.match(/[^:]*$/)[0];
              if (msgType != 'Success') {
                let msg = 'unspecified';
                if (status[0].StatusMessage) {
                  msg = status[0].StatusMessage[0]._;
                } else if (statusCode[0].StatusCode) {
                  msg = statusCode[0].StatusCode[0].$.Value.match(/[^:]*$/)[0];
                }
                const error = new Error(`SAML provider returned ${msgType} error: ${msg}`);
                const builderOpts = {
                  rootName: 'Status',
                  headless: true
                };
                error.statusXml = new xml2js.Builder(builderOpts).buildObject(status[0]);
                throw error;
              }
            }
          }
          throw new Error('Missing SAML assertion');
        }
      } else {
        if (this.options.cert && !validSignature) {
          throw new Error('Invalid signature: No response found');
        }
        const logoutResponse = doc2.LogoutResponse;
        if (logoutResponse) {
          return callback(null, null, true);
        } else {
          throw new Error('Unknown SAML response message');
        }
      }
    })()
    .catch(async err => {
      debug('validatePostResponse resulted in an error: %s', err);
      if (this.options.validateInResponseTo) {
        const removeFn = promisify(this.cacheProvider.remove).bind(this.cacheProvider);
        await removeFn(inResponseTo);
        callback(err);
      } else {
        callback(err);
      }
    });
  }

  validateRedirect(container, originalQuery, callback) {
    const samlMessageType = container.SAMLRequest ? 'SAMLRequest' : 'SAMLResponse';

    const data = Buffer.from(container[samlMessageType], 'base64');
    zlib.inflateRaw(data, (err, inflated) => {
      if (err) {
        return callback(err);
      }

      const xmlParser = new XMLParser(inflated.toString());

      (async () => {
        if (samlMessageType === 'SAMLResponse') {
          await this._verifyLogoutResponse(xmlParser);
        } else {
          await this._verifyLogoutRequest(xmlParser);
        }
        await this._hasValidSignatureForRedirect(container, originalQuery);
        return processValidlySignedSamlLogout(this, xmlParser, callback);
      })()
      .catch(callback);

    });
  }

  validatePostRequest({ SAMLRequest }, callback) {
    const xml = Buffer.from(SAMLRequest, 'base64').toString('utf8');

    (async () => {
      const certs = await this._certsToCheck();
      const xmlParser = new XMLParser(xml, {signaturePublicKeys: certs});

      // Check if this document has a valid top-level signature
      if (this.options.cert && !xmlParser.signatureVerified) {
        throw new Error('Invalid signature on documentElement');
      }

      return processValidlySignedPostRequest(this, xmlParser, callback);
    })()
    .catch(callback);
  }

  generateServiceProviderMetadata(decryptionCert, signingCert) {
    const metadata = {
      'EntityDescriptor': {
        '@xmlns': 'urn:oasis:names:tc:SAML:2.0:metadata',
        '@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
        '@entityID': this.options.issuer,
        '@ID': this.options.issuer.replace(/\W/g, '_'),
        'SPSSODescriptor': {
          '@protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:2.0:protocol',
        },
      }
    };

    if (this.options.decryptionPvk) {
      if (!decryptionCert) {
        throw new Error('Missing decryptionCert while generating metadata for decrypting service provider');
      }
    }

    if (this.options.privateCert) {
      if (!signingCert) {
        throw new Error('Missing signingCert while generating metadata for signing service provider messages');
      }
    }

    if (this.options.decryptionPvk || this.options.privateCert) {
      metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor = [];
      if (this.options.privateCert) {

        signingCert = signingCert.replace(/-+BEGIN CERTIFICATE-+\r?\n?/, '');
        signingCert = signingCert.replace(/-+END CERTIFICATE-+\r?\n?/, '');
        signingCert = signingCert.replace(/\r\n/g, '\n');

        metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor.push({
          '@use': 'signing',
          'ds:KeyInfo': {
            'ds:X509Data': {
              'ds:X509Certificate': {
                '#text': signingCert
              }
            }
          }
        });
      }

      if (this.options.decryptionPvk) {

        decryptionCert = decryptionCert.replace(/-+BEGIN CERTIFICATE-+\r?\n?/, '');
        decryptionCert = decryptionCert.replace(/-+END CERTIFICATE-+\r?\n?/, '');
        decryptionCert = decryptionCert.replace(/\r\n/g, '\n');

        metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor.push({
          '@use': 'encryption',
          'ds:KeyInfo': {
            'ds:X509Data': {
              'ds:X509Certificate': {
                '#text': decryptionCert
              }
            }
          },
          'EncryptionMethod': [
            // this should be the set that the xmlenc library supports
            { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes256-cbc' },
            { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes128-cbc' },
            { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc' }
          ]
        });
      }
    }

    if (this.options.logoutCallbackUrl) {
      metadata.EntityDescriptor.SPSSODescriptor.SingleLogoutService = {
        '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        '@Location': this.options.logoutCallbackUrl
      };
    }

    if (this.options.identifierFormat) {
      metadata.EntityDescriptor.SPSSODescriptor.NameIDFormat = this.options.identifierFormat;
    }

    metadata.EntityDescriptor.SPSSODescriptor.AssertionConsumerService = {
      '@index': '1',
      '@isDefault': 'true',
      '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      '@Location': this._getCallbackUrl({})
    };
    return xmlbuilder.create(metadata).end({ pretty: true, indent: '  ', newline: '\n' });
  }

  // private methods
  _getProtocol({ protocol }) {
    return this.options.protocol || (protocol || 'http').concat('://');
  }

  _getCallbackUrl(req) {
    // Post-auth destination
    if (this.options.callbackUrl) {
      return this.options.callbackUrl;
    } else {
      let host;
      if (req.headers) {
        host = req.headers.host;
      } else {
        host = this.options.host;
      }
      return this._getProtocol(req) + host + this.options.path;
    }
  }

  _generateUniqueID() {
    return crypto.randomBytes(10).toString('hex');
  }

  _generateInstant() {
    return new Date().toISOString();
  }

  _signRequest(samlMessage) {
    let signer;
    const samlMessageToSign = {};
    samlMessage.SigAlg = algorithms.getSigningAlgorithm(this.options.signatureAlgorithm);
    signer = algorithms.getSigner(this.options.signatureAlgorithm);
    if (samlMessage.SAMLRequest) {
      samlMessageToSign.SAMLRequest = samlMessage.SAMLRequest;
    }
    if (samlMessage.SAMLResponse) {
      samlMessageToSign.SAMLResponse = samlMessage.SAMLResponse;
    }
    if (samlMessage.RelayState) {
      samlMessageToSign.RelayState = samlMessage.RelayState;
    }
    if (samlMessage.SigAlg) {
      samlMessageToSign.SigAlg = samlMessage.SigAlg;
    }
    signer.update(querystring.stringify(samlMessageToSign));
    samlMessage.Signature = signer.sign(this._keyToPEM(this.options.privateCert), 'base64');
  }

  async _generateAuthorizeRequest(req, isPassive, isHttpPostBinding) {
    const id = `_${this._generateUniqueID()}`;
    const instant = this._generateInstant();
    const forceAuthn = this.options.forceAuthn || false;

    if (this.options.validateInResponseTo) {
      const saveFn = promisify(this.cacheProvider.save).bind(this.cacheProvider);
      await saveFn(id, instant);
    }

    const request = {
      'samlp:AuthnRequest': {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@ID': id,
        '@Version': '2.0',
        '@IssueInstant': instant,
        '@ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        '@Destination': this.options.entryPoint,
        'saml:Issuer': {
          '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
          '#text': this.options.issuer
        }
      }
    };

    if (isPassive) {
      request['samlp:AuthnRequest']['@IsPassive'] = true;
    }

    if (forceAuthn) {
      request['samlp:AuthnRequest']['@ForceAuthn'] = true;
    }

    if (!this.options.disableRequestACSUrl) {
      request['samlp:AuthnRequest']['@AssertionConsumerServiceURL'] = this._getCallbackUrl(req);
    }

    if (this.options.identifierFormat) {
      request['samlp:AuthnRequest']['samlp:NameIDPolicy'] = {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@Format': this.options.identifierFormat,
        '@AllowCreate': 'true'
      };
    }

    if (!this.options.disableRequestedAuthnContext) {
      const authnContextClassRefs = [];
      this.options.authnContext.forEach(value => {
        authnContextClassRefs.push({
          '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
          '#text': value
        });
      });

      request['samlp:AuthnRequest']['samlp:RequestedAuthnContext'] = {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@Comparison': this.options.RACComparison,
        'saml:AuthnContextClassRef': authnContextClassRefs
      };
    }

    if (this.options.attributeConsumingServiceIndex != null) {
      request['samlp:AuthnRequest']['@AttributeConsumingServiceIndex'] = this.options.attributeConsumingServiceIndex;
    }

    if (this.options.providerName) {
      request['samlp:AuthnRequest']['@ProviderName'] = this.options.providerName;
    }

    let stringRequest = xmlbuilder.create(request).end();
    if (isHttpPostBinding && this.options.privateCert) {
      stringRequest = signAuthnRequestPost(stringRequest, this.options);
    }

    return stringRequest;
  }

  async _generateLogoutRequest({ user }) {
    const id = `_${this._generateUniqueID()}`;
    const instant = this._generateInstant();

    const request = {
      'samlp:LogoutRequest': {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '@ID': id,
        '@Version': '2.0',
        '@IssueInstant': instant,
        '@Destination': this.options.logoutUrl,
        'saml:Issuer': {
          '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
          '#text': this.options.issuer
        },
        'saml:NameID': {
          '@Format': user.nameIDFormat,
          '#text': user.nameID
        }
      }
    };

    if (user.nameQualifier != null) {
      request['samlp:LogoutRequest']['saml:NameID']['@NameQualifier'] = user.nameQualifier;
    }

    if (user.spNameQualifier != null) {
      request['samlp:LogoutRequest']['saml:NameID']['@SPNameQualifier'] = user.spNameQualifier;
    }

    if (user.sessionIndex) {
      request['samlp:LogoutRequest']['saml2p:SessionIndex'] = {
        '@xmlns:saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '#text': user.sessionIndex
      };
    }
    const saveFn = promisify(this.cacheProvider.save).bind(this.cacheProvider);
    await saveFn(id, instant);
    return xmlbuilder.create(request).end();
  }

  _generateLogoutResponse(req, { ID }) {
    const id = `_${this._generateUniqueID()}`;
    const instant = this._generateInstant();

    const request = {
      'samlp:LogoutResponse': {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '@ID': id,
        '@Version': '2.0',
        '@IssueInstant': instant,
        '@Destination': this.options.logoutUrl,
        '@InResponseTo': ID,
        'saml:Issuer': {
          '#text': this.options.issuer
        },
        'samlp:Status': {
          'samlp:StatusCode': {
            '@Value': 'urn:oasis:names:tc:SAML:2.0:status:Success'
          }
        }
      }
    };

    return xmlbuilder.create(request).end();
  }

  _requestToUrl(request, response, operation, additionalParameters, callback) {

    const requestToUrlHelper = (err, buffer) => {
      if (err) {
        return callback(err);
      }

      const base64 = buffer.toString('base64');
      let target = url.parse(this.options.entryPoint, true);

      if (operation === 'logout') {
        if (this.options.logoutUrl) {
          target = url.parse(this.options.logoutUrl, true);
        }
      } else if (operation !== 'authorize') {
        return callback(new Error(`Unknown operation: ${operation}`));
      }

      const samlMessage = request ? {SAMLRequest: base64} : {SAMLResponse: base64};
      Object.keys(additionalParameters).forEach(k => {
        samlMessage[k] = additionalParameters[k];
      });

      if (this.options.privateCert) {
        try {
          if (!this.options.entryPoint) {
            throw new Error('"entryPoint" config parameter is required for signed messages');
          }

          // sets .SigAlg and .Signature
          this._signRequest(samlMessage);

        } catch (ex) {
          return callback(ex);
        }
      }
      Object.keys(samlMessage).forEach(k => {
        target.query[k] = samlMessage[k];
      });

      // Delete 'search' to for pulling query string from 'query'
      // https://nodejs.org/api/url.html#url_url_format_urlobj
      delete target.search;

      callback(null, url.format(target));
    };

    if (this.options.skipRequestCompression) {
      requestToUrlHelper(null, Buffer.from(request || response, 'utf8'));
    } else {

      zlib.deflateRaw(request || response, requestToUrlHelper);
    }
  }

  _getAdditionalParams({ query, body }, operation, overrideParams) {
    const additionalParams = {};

    const RelayState = query && query.RelayState || body && body.RelayState;
    if (RelayState) {
      additionalParams.RelayState = RelayState;
    }

    const optionsAdditionalParams = this.options.additionalParams || {};
    Object.keys(optionsAdditionalParams).forEach(k => {
      additionalParams[k] = optionsAdditionalParams[k];
    });

    let optionsAdditionalParamsForThisOperation = {};
    if (operation === 'authorize') {
      optionsAdditionalParamsForThisOperation = this.options.additionalAuthorizeParams || {};
    }
    if (operation === 'logout') {
      optionsAdditionalParamsForThisOperation = this.options.additionalLogoutParams || {};
    }

    Object.keys(optionsAdditionalParamsForThisOperation).forEach(k => {
      additionalParams[k] = optionsAdditionalParamsForThisOperation[k];
    });

    overrideParams = overrideParams || {};
    Object.keys(overrideParams).forEach(k => {
      additionalParams[k] = overrideParams[k];
    });

    return additionalParams;
  }

  _certToPEM(cert) {
    cert = cert.match(/.{1,64}/g).join('\n');

    if (!cert.includes('-BEGIN CERTIFICATE-')) {cert = `-----BEGIN CERTIFICATE-----\n${cert}`;}
    if (!cert.includes('-END CERTIFICATE-')) {cert = `${cert}\n-----END CERTIFICATE-----\n`;}

    return cert;
  }

  async _certsToCheck() {
    if (!this.options.cert) {
      return [];
    }
    if (typeof (this.options.cert) === 'function') {
      let certs = await promisify(this.options.cert)();
      if (!Array.isArray(certs)) {
        certs = [certs];
      }
      return certs;
    }
    let certs = this.options.cert;
    if (!Array.isArray(certs)) {
      certs = [certs];
    }
    return certs;
  }

  async _validateInResponseTo(inResponseTo) {
    if (this.options.validateInResponseTo) {
      if (inResponseTo) {
        const getFn = promisify(this.cacheProvider.get).bind(this.cacheProvider);
        const result = await getFn(inResponseTo);
        if (!result) {throw new Error('InResponseTo is not valid');}
        return;
      } else {
        throw new Error('InResponseTo is missing from response');
      }
    } else {
      return;
    }
  }

  async _hasValidSignatureForRedirect({ Signature, SigAlg }, originalQuery) {
    const tokens = originalQuery.split('&');
    const getParam = key => {
      const exists = tokens.filter(t => new RegExp(key).test(t));
      return exists[0];
    };

    if (Signature && this.options.cert) {
      let urlString = getParam('SAMLRequest') || getParam('SAMLResponse');

      if (getParam('RelayState')) {
        urlString += `&${getParam('RelayState')}`;
      }

      urlString += `&${getParam('SigAlg')}`;

      const certs = await this._certsToCheck();

      const hasValidQuerySignature = certs.some(cert => this._validateSignatureForRedirect(
        urlString, Signature, SigAlg, cert
      ));

      if (!hasValidQuerySignature) {
        throw 'Invalid signature';
      }
      return true;
    } else {
      return true;
    }
  }

  _validateSignatureForRedirect(urlString, signature, alg, cert) {
    // See if we support a matching algorithm, case-insensitive. Otherwise, throw error.
    function hasMatch(ourAlgo) {
      // The incoming algorithm is forwarded as a URL.
      // We trim everything before the last # get something we can compare to the Node.js list
      const algFromURI = alg.toLowerCase().replace(/.*#(.*)$/, '$1');
      return ourAlgo.toLowerCase() === algFromURI;
    }
    let i = crypto.getHashes().findIndex(hasMatch);
    let matchingAlgo;
    if (i > -1) {
      matchingAlgo = crypto.getHashes()[i];
    }
    else {
      throw `${alg} is not supported`;
    }

    const verifier = crypto.createVerify(matchingAlgo);
    verifier.update(urlString);

    return verifier.verify(this._certToPEM(cert), signature, 'base64');
  }

  async _verifyLogoutRequest(xmlParser) {
    const issuer = xmlParser.query('/saml2p:LogoutRequest/claim:Issuer')[0].firstChild.data;
    this._verifyIssuer(issuer);
    const nowMs = new Date().getTime();
    const NotOnOrAfter = xmlParser.query('/samlp:LogoutRequest')[0].getAttribute('NotOnOrAfter');
    const NotBefore = xmlParser.query('/samlp:LogoutRequest')[0].getAttribute('NotBefore');
    const conErr = this._checkTimestampsValidityError(nowMs, NotBefore, NotOnOrAfter);
    if (conErr) {
      throw conErr;
    }
  }

  async _verifyLogoutResponse(xmlParser) {
    const statusCode = xmlParser.query('/saml2p:LogoutResponse/samlp:Status/samlp:StatusCode')[0].getAttribute('Value');
    if (statusCode !== 'urn:oasis:names:tc:SAML:2.0:status:Success') {throw `Bad status code: ${statusCode}`;}

    const issuer = xmlParser.query('/saml2p:LogoutResponse/claim:Issuer')[0].firstChild.data;
    this._verifyIssuer(issuer);
    const inResponseTo = xmlParser.query('/saml2p:LogoutResponse')[0].getAttribute('InResponseTo');

    if (inResponseTo) {
      return this._validateInResponseTo(inResponseTo);
    }

    return true;
  }

  _verifyIssuer(issuer) {
    if (this.options.idpIssuer) {
      if (issuer) {
        if (issuer !== this.options.idpIssuer) {throw `Unknown SAML issuer. Expected: ${this.options.idpIssuer} Received: ${issuer}`;}
      } else {
        throw 'Missing SAML issuer';
      }
    }
  }

  _processValidlySignedAssertion(xml, samlResponseXml, inResponseTo, callback) {
    let msg;
    const parserConfig = {
      explicitRoot: true,
      explicitCharkey: true,
      tagNameProcessors: [xml2js.processors.stripPrefix]
    };
    const nowMs = new Date().getTime();
    const profile = {};
    let assertion;
    let parsedAssertion;
    const parser = new xml2js.Parser(parserConfig);
    parser.parseStringPromise(xml)
      .then(doc => {
        parsedAssertion = doc;
        assertion = doc.Assertion;

        const issuer = assertion.Issuer;
        if (issuer && issuer[0]._) {
          profile.issuer = issuer[0]._;
        }

        if (inResponseTo) {
          profile.inResponseTo = inResponseTo;
        }

        const authnStatement = assertion.AuthnStatement;
        if (authnStatement) {
          if (authnStatement[0].$ && authnStatement[0].$.SessionIndex) {
            profile.sessionIndex = authnStatement[0].$.SessionIndex;
          }
        }

        const subject = assertion.Subject;
        let subjectConfirmation;
        let confirmData;
        if (subject) {
          const nameID = subject[0].NameID;
          if (nameID && nameID[0]._) {
            profile.nameID = nameID[0]._;

            if (nameID[0].$ && nameID[0].$.Format) {
              profile.nameIDFormat = nameID[0].$.Format;
              profile.nameQualifier = nameID[0].$.NameQualifier;
              profile.spNameQualifier = nameID[0].$.SPNameQualifier;
            }
          }

          subjectConfirmation = subject[0].SubjectConfirmation ?
            subject[0].SubjectConfirmation[0] : null;
          confirmData = subjectConfirmation && subjectConfirmation.SubjectConfirmationData ?
            subjectConfirmation.SubjectConfirmationData[0] : null;
          if (subject[0].SubjectConfirmation && subject[0].SubjectConfirmation.length > 1) {
            msg = 'Unable to process multiple SubjectConfirmations in SAML assertion';
            throw new Error(msg);
          }

          if (subjectConfirmation) {
            if (confirmData && confirmData.$) {
              const subjectNotBefore = confirmData.$.NotBefore;
              const subjectNotOnOrAfter = confirmData.$.NotOnOrAfter;

              const subjErr = this._checkTimestampsValidityError(
                nowMs, subjectNotBefore, subjectNotOnOrAfter);
              if (subjErr) {
                throw subjErr;
              }
            }
          }
        }

        // Test to see that if we have a SubjectConfirmation InResponseTo that it matches
        // the 'InResponseTo' attribute set in the Response
        if (this.options.validateInResponseTo) {
          const removeFn = promisify(this.cacheProvider.remove).bind(this.cacheProvider);
          const getFn = promisify(this.cacheProvider.get).bind(this.cacheProvider);
          if (subjectConfirmation) {
            if (confirmData && confirmData.$) {
              const subjectInResponseTo = confirmData.$.InResponseTo;
              if (inResponseTo && subjectInResponseTo && subjectInResponseTo != inResponseTo) {
                return removeFn(inResponseTo)
                  .then(() => {
                    throw new Error('InResponseTo is not valid');
                  });
              } else if (subjectInResponseTo) {
                let foundValidInResponseTo = false;

                return getFn(subjectInResponseTo)
                  .then(result => {
                    if (result) {
                      const createdAt = new Date(result);
                      if (nowMs < createdAt.getTime() + this.options.requestIdExpirationPeriodMs)
                        {foundValidInResponseTo = true;}
                    }
                    return removeFn(inResponseTo);
                  })
                  .then(() => {
                    if (!foundValidInResponseTo) {
                      throw new Error('InResponseTo is not valid');
                    }
                    return Promise.resolve();
                  });
              }
            }
          } else {
            return removeFn(inResponseTo);
          }
        } else {
          return Promise.resolve();
        }
      })
      .then(() => {
        const conditions = assertion.Conditions ? assertion.Conditions[0] : null;
        if (assertion.Conditions && assertion.Conditions.length > 1) {
          msg = 'Unable to process multiple conditions in SAML assertion';
          throw new Error(msg);
        }
        if (conditions && conditions.$) {
          const conErr = this._checkTimestampsValidityError(nowMs, conditions.$.NotBefore, conditions.$.NotOnOrAfter);
          if (conErr) {throw conErr;}
        }

        if (this.options.audience) {
          const audienceErr = this._checkAudienceValidityError(this.options.audience, conditions.AudienceRestriction);
          if (audienceErr) {throw audienceErr;}
        }

        const attributeStatement = assertion.AttributeStatement;
        if (attributeStatement) {
          const attributes = [].concat(...attributeStatement.filter(({ Attribute }) => Array.isArray(Attribute))
            .map(({ Attribute }) => Attribute));

          const attrValueMapper = value => typeof value === 'string' ? value : value._;

          if (attributes) {
            attributes.forEach(attribute => {
              if (!Object.prototype.hasOwnProperty.call(attribute, 'AttributeValue')) {
                // if attributes has no AttributeValue child, continue
                return;
              }
              const value = attribute.AttributeValue;
              if (value.length === 1) {
                profile[attribute.$.Name] = attrValueMapper(value[0]);
              } else {
                profile[attribute.$.Name] = value.map(attrValueMapper);
              }
            });
          }
        }

        if (!profile.mail && profile['urn:oid:0.9.2342.19200300.100.1.3']) {
          // See https://spaces.internet2.edu/display/InCFederation/Supported+Attribute+Summary
          // for definition of attribute OIDs
          profile.mail = profile['urn:oid:0.9.2342.19200300.100.1.3'];
        }

        if (!profile.email && profile.mail) {
          profile.email = profile.mail;
        }

        profile.getAssertionXml = () => xml;
        profile.getAssertion = () => parsedAssertion;
        profile.getSamlResponseXml = () => samlResponseXml;

        callback(null, profile, false);
      })
      .catch(err => callback(err));
  }

  _checkTimestampsValidityError(nowMs, notBefore, notOnOrAfter) {
    if (this.options.acceptedClockSkewMs === -1) {return null;}

    if (notBefore) {
      const notBeforeMs = Date.parse(notBefore);
      if (nowMs + this.options.acceptedClockSkewMs < notBeforeMs) {return new Error('SAML assertion not yet valid');}
    }
    if (notOnOrAfter) {
      const notOnOrAfterMs = Date.parse(notOnOrAfter);
      if (nowMs - this.options.acceptedClockSkewMs >= notOnOrAfterMs) {return new Error('SAML assertion expired');}
    }

    return null;
  }

  _checkAudienceValidityError(expectedAudience, audienceRestrictions) {
    if (!audienceRestrictions || audienceRestrictions.length < 1) {
      return new Error('SAML assertion has no AudienceRestriction');
    }
    const errors = audienceRestrictions.map(({ Audience }) => {
      if (!Audience || !Audience[0] || !Audience[0]._) {
        return new Error('SAML assertion AudienceRestriction has no Audience value');
      }
      if (Audience[0]._ !== expectedAudience) {
        return new Error('SAML assertion audience mismatch');
      }
      return null;
    }).filter(result => result !== null);
    if (errors.length > 0) {
      return errors[0];
    }
    return null;
  }

  async _getNameID({ options }, xmlParser) {
    const nameIds = xmlParser.query('/saml2p:LogoutRequest/claim:NameID');
    const encryptedIds = xmlParser.query('/saml2p:LogoutRequest/claim:EncryptedID');

    if (nameIds.length + encryptedIds.length > 1) {
      throw new Error('Invalid LogoutRequest');
    }
    if (nameIds.length === 1) {
      return returnNameID(nameIds[0]);
    }
    if (encryptedIds.length === 1) {
      if (!options.decryptionPvk) {
        throw new Error('No decryption key for encrypted SAML response');
      }
      const encryptedDatas = xmlParser.query('/saml2p:LogoutRequest/claim:EncryptedID/enc:EncryptedData');

      if (encryptedDatas.length !== 1) {
        throw new Error('Invalid LogoutRequest');
      }
      const encryptedDataXml = encryptedDatas[0].toString();

      const xmlencOptions = { key: options.decryptionPvk };
      const decryptFn = promisify(xmlenc.decrypt).bind(xmlenc);

      const decryptedXml = await decryptFn(encryptedDataXml, xmlencOptions);
      const decryptedXmlParser = new XMLParser(decryptedXml);
      const decryptedIds = decryptedXmlParser.query('/*[local-name()=\'NameID\']');

      if (decryptedIds.length !== 1) {
        throw new Error('Invalid EncryptedAssertion content');
      }
      return returnNameID(decryptedIds[0]);

    }
    throw new Error('Missing SAML NameID');
  }

  _keyToPEM(key) {
    if (!key || typeof key !== 'string') {return key;}

    const lines = key.split('\n');
    if (lines.length !== 1) {return key;}

    const wrappedKey = [
      '-----BEGIN PRIVATE KEY-----',
      ...key.match(/.{1,64}/g),
      '-----END PRIVATE KEY-----',
      ''
    ].join('\n');
    return wrappedKey;
  }
}

function processValidlySignedSamlLogout(self, xmlParser, callback) {
  const request = xmlParser.query('/saml2p:LogoutRequest')[0];
  const response = xmlParser.query('/saml2p:LogoutResponse')[0];

  if (response) {
    return callback(null, null, true);
  } else if (request) {
    return processValidlySignedPostRequest(self, xmlParser, callback);
  } else {
    throw new Error('Unknown SAML response message');
  }
}

function returnNameID(nameid) {
  const format = xpath(nameid, '@Format');
  return {
    value: nameid.textContent,
    format: format && format[0] && format[0].nodeValue
  };
}

function processValidlySignedPostRequest(self, xmlParser, callback) {
  const request = xmlParser.query('/saml2p:LogoutRequest')[0];
  if (request) {
    const profile = {};

    const ID = request.getAttribute('ID');
    if (ID) {
      profile.ID = ID;
    } else {
      return callback(new Error('Missing SAML LogoutRequest ID'));
    }
    const issuer = xmlParser.query('/saml2p:LogoutRequest/claim:Issuer')[0].firstChild.data;
    if (issuer) {
      profile.issuer = issuer;
    } else {
      return callback(new Error('Missing SAML issuer'));
    }

    return self._getNameID(self, xmlParser)
    .then((nameID) => {
      if (nameID) {
        profile.nameID = nameID.value;
        if (nameID.format) {
          profile.nameIDFormat = nameID.format;
        }
      } else {
        throw new Error('Missing SAML NameID');
      }

      const sessionIndexes = xmlParser.query('/saml2p:LogoutRequest/samlp:SessionIndex');
      if (sessionIndexes.length) {
        const sessionIndex = sessionIndexes[0].firstChild.data;
        profile.sessionIndex = sessionIndex;
      }
      return callback(null, profile, true);
    })
    .catch(callback);
  } else {
    return callback(new Error('Unknown SAML request message'));
  }
}

exports.SAML = SAML;
