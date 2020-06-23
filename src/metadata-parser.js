
const {XMLParser} = require('./xml-parser');

class MetadataParser extends XMLParser {
  constructor(xml, {
    signaturePublicKeys
  } = {}) {
    super(xml, {signaturePublicKeys});
    this.namespaces.md = 'urn:oasis:names:tc:SAML:2.0:metadata';
  }

  get signingCertificates() {
    return this._getCertificates('signing');
  }

  get encryptionCertificates() {
    return this._getCertificates('encryption');
  }

  get SSOServices() {
    return this.query('//md:IDPSSODescriptor/md:SingleSignOnService').map(node => ({
      binding: node.getAttribute('Binding'),
      location: node.getAttribute('Location'),
      type: node.getAttribute('Binding').replace('urn:oasis:names:tc:SAML:2.0:bindings:', '')
    }));
  }

  _getCertificates(type = 'signing') {
    const q = `//md:IDPSSODescriptor/md:KeyDescriptor[@use="${type}" or not(@use)]/sig:KeyInfo/sig:X509Data/sig:X509Certificate`;
    return this.query(q).map(node => node.firstChild.data.replace(/\r?\n/g, '').trim());
  }

}

exports.MetadataParser = MetadataParser;
