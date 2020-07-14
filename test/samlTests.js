'use strict';
var fs = require('fs');
var should = require('should');

var SAML = require('../src/saml.js').SAML;

describe('SAML.js', function () {
  describe('get Urls', function () {
    var saml, req, options;
    beforeEach(function () {
      saml = new SAML({
        entryPoint: 'https://exampleidp.com/path?key=value',
        logoutUrl: 'https://exampleidp.com/path?key=value'
      });
      req = {
        protocol: 'https',
        headers: {
          host: 'examplesp.com'
        },
        user: {
          nameIDFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
          nameID: 'nameID'
        },
        samlLogoutRequest: {
          ID: 123
        }
      };
      options = {
        additionalParams: {
          additionalKey: 'additionalValue'
        }
      };
    });

    describe('getAuthorizeUrl', function () {
      it('returns with right host', async function () {
        const target = await saml.getAuthorizeUrl();

        new URL(target).host.should.equal('exampleidp.com');
      });
      it('returns with right protocol', async function () {
        const target = await saml.getAuthorizeUrl();

        new URL(target).protocol.should.equal('https:');
      });
      it('returns with right path', async function () {
        const target = await saml.getAuthorizeUrl();

        new URL(target).pathname.should.equal('/path');
      });
      it('returns with original query string', async function () {
        const target = await saml.getAuthorizeUrl();

        new URL(target).searchParams.get('key').should.equal('value');
      });
      it('returns with additional run-time params in query string', async function () {
        const target = await saml.getAuthorizeUrl(options);
        const searchParams = new URL(target).searchParams;
        [...searchParams.keys()].should.have.length(3);
        should.equal(searchParams.get('key'), 'value');
        searchParams.get('SAMLRequest').should.not.be.empty();
        should.equal(searchParams.get('additionalKey'), 'additionalValue');
      });
      // NOTE: This test only tests existence of the assertion, not the correctness
      it('returns with saml request object', async function () {
        const target = await saml.getAuthorizeUrl();

        should(new URL(target).searchParams.has('SAMLRequest')).be.true;
      });
    });

    describe('getLogoutUrl', function () {
      it('returns with right host', async function () {
        const target = await saml.getLogoutUrl(req.user);
        new URL(target).host.should.equal('exampleidp.com');
      });
      it('returns with right protocol', async function () {
        const target = await saml.getLogoutUrl(req.user);

        new URL(target).protocol.should.equal('https:');
      });
      it('returns with right path', async function () {
        const target = await saml.getLogoutUrl(req.user);

        new URL(target).pathname.should.equal('/path');
      });
      it('returns with original query string', async function () {
        const target = await saml.getLogoutUrl(req.user);

        new URL(target).searchParams.get('key').should.equal('value');
      });
      it('returns with additional run-time params in query string', async function () {
        const target = await saml.getLogoutUrl(req.user, options);
        const searchParams = new URL(target).searchParams;
        [...searchParams.keys()].should.have.length(3);
        searchParams.get('key').should.equal('value');
        searchParams.get('SAMLRequest').should.not.be.empty();
        should.equal(searchParams.get('additionalKey'), 'additionalValue');
      });
      // NOTE: This test only tests existence of the assertion, not the correctness
      it('returns with saml request object', async function () {
        const target = await saml.getLogoutUrl(req.user);

        should(new URL(target).searchParams.has('SAMLRequest')).be.true;
      });
    });

    describe('getLogoutResponseUrl', function () {
      it('returns with right host', async function () {
        const target = await saml.getLogoutResponseUrl({user: req.user, samlLogoutRequest: req.samlLogoutRequest});

        new URL(target).host.should.equal('exampleidp.com');
      });
      it('returns with right protocol', async function () {
        const target = await saml.getLogoutResponseUrl({user: req.user, samlLogoutRequest: req.samlLogoutRequest});

        new URL(target).protocol.should.equal('https:');
      });
      it('returns with right path', async function () {
        const target = await saml.getLogoutResponseUrl({user: req.user, samlLogoutRequest: req.samlLogoutRequest});

        new URL(target).pathname.should.equal('/path');
      });
      it('returns with original query string', async function () {
        const target = await saml.getLogoutResponseUrl({user: req.user, samlLogoutRequest: req.samlLogoutRequest});

        new URL(target).searchParams.get('key').should.equal('value');
      });
      it('returns with additional run-time params in query string', async function () {
        const target = await saml.getLogoutResponseUrl({user: req.user, samlLogoutRequest: req.samlLogoutRequest}, options);
        const searchParams = new URL(target).searchParams;
        [...searchParams.keys()].should.have.length(3);
        searchParams.get('key').should.equal('value');
        searchParams.get('SAMLResponse').should.not.be.empty();
        searchParams.get('additionalKey').should.equal('additionalValue');

      });
      // NOTE: This test only tests existence of the assertion, not the correctness
      it('returns with saml response object', async function () {
        const target = await saml.getLogoutResponseUrl({user: req.user, samlLogoutRequest: req.samlLogoutRequest});

        new URL(target).searchParams.get('SAMLResponse').should.not.be.empty();
      });
    });

    describe('_keyToPEM', function () {
      var [regular, singleline] = [
        'acme_tools_com.key',
        'singleline_acme_tools_com.key'
      ].map(keyFromFile);

      it('formats singleline keys properly', function (done) {
        var result = saml._keyToPEM(singleline);
        result.should.equal(regular);
        done();
      });

      it('passes all other multiline keys', function (done) {
        var result = saml._keyToPEM(regular);
        result.should.equal(regular);
        done();
      });

      it('does nothing to falsy', function (done) {
        var result = saml._keyToPEM(null);
        should.equal(result, null);
        done();
      });

      it('does nothing to non strings', function (done) {
        var result = saml._keyToPEM(1);
        should.equal(result, 1);
        done();
      });
    });
  });
});

function keyFromFile (file) {
  return fs.readFileSync(`./test/static/${file}`).toString();
}
