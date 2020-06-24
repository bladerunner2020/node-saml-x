const {SignedXml} = require('xml-crypto');
const xmldom = require('xmldom');
const xpath = require('xpath');

class XMLParser {
  constructor(xml, {
    signaturePublicKeys,
    additionalNamespaces = {}
  } = {}) {

    this.xml = xml;
    this.namespaces = {
      sig: 'http://www.w3.org/2000/09/xmldsig#',
      saml2p: 'urn:oasis:names:tc:SAML:2.0:protocol',
      samlp: 'urn:oasis:names:tc:SAML:2.0:protocol',
      claim: 'urn:oasis:names:tc:SAML:2.0:assertion',
      enc: 'http://www.w3.org/2001/04/xmlenc#',
      ...additionalNamespaces
    };

    this.parsedXml = new xmldom.DOMParser({}).parseFromString(xml);

    this.signatureVerified = Boolean(signaturePublicKeys) && this.verifySignature(signaturePublicKeys);
  }

  query(q) {
    return xpath.useNamespaces(this.namespaces)(q, this.parsedXml);
  }

  // This function checks that the |currentNode| in the |xml| document contains exactly 1 valid
  //   signature of the |currentNode|.
  //
  // See https://github.com/bergie/passport-saml/issues/19 for references to some of the attack
  //   vectors against SAML signature verification.
  verifySignature(signaturePublicKeys, currentNodeQuery) {
    if (!Array.isArray(signaturePublicKeys)) {
      signaturePublicKeys = [signaturePublicKeys];
    }
    return signaturePublicKeys.some(signaturePublicKey => this._verifySignatureForKey(signaturePublicKey, currentNodeQuery));
  }

  // This function checks that the |signature| is signed with a given |signaturePublicKey|.
  _verifySignatureForKey(signaturePublicKey, currentNodeQuery = '/*') {
    const signatures = this.query('//sig:Signature');
    // This function is expecting to validate exactly one signature, so if we find more or fewer than that, reject.
    if (signatures.length !== 1) {
      return false;
    }
    const signature = signatures[0];

    const sig = new SignedXml();
    sig.keyInfoProvider = {
      getKeyInfo: () => '<X509Data></X509Data>',
      getKey: () => signaturePublicKey
    };
    sig.loadSignature(signature);

    // We expect each signature to contain exactly one reference to the top level of the
    // xml we are validating, so if we see anything else, reject.
    if (sig.references.length !== 1) {return false;}

    const refUri = sig.references[0].uri;
    const refId = (refUri[0] === '#') ? refUri.substring(1) : refUri;
    // If we can't find the reference at the top level, reject
    const currentNode = this.query(currentNodeQuery)[0];
    const idAttribute = currentNode.getAttribute('ID') ? 'ID' : 'Id';
    if (currentNode.getAttribute(idAttribute) != refId) {return false;}

    // If we find any extra referenced nodes, reject.
    // (xml-crypto only verifies one digest, so multiple candidate references is bad news)
    const totalReferencedNodes = xpath.select(`//*[@${idAttribute}='${refId}']`, currentNode.ownerDocument);
    if (totalReferencedNodes.length > 1) {return false;}

    return sig.checkSignature(this.xml);
  }

}

exports.XMLParser = XMLParser;
