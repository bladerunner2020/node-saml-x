'use strict';
const should       = require( 'should' );
const parseString  = require( 'xml2js' ).parseString;
const SAML         = require( '../src/index.js' ).SAML;
const fs           = require( 'fs' );
const sinon        = require('sinon');
const {URL}        = require('url');

// a certificate which is re-used by several tests
const TEST_CERT = 'MIIEFzCCAv+gAwIBAgIUFJsUjPM7AmWvNtEvULSHlTTMiLQwDQYJKoZIhvcNAQEFBQAwWDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFN1YnNwYWNlMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgNDIzNDkwHhcNMTQwNTEzMTgwNjEyWhcNMTkwNTE0MTgwNjEyWjBYMQswCQYDVQQGEwJVUzERMA8GA1UECgwIU3Vic3BhY2UxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA0MjM0OTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKrAzJdY9FzFLt5blArJfPzgi87EnFGlTfcV5T1TUDwLBlDkY/0ZGKnMOpf3D7ie2C4pPFOImOogcM5kpDDL7qxTXZ1ewXVyjBdMu29NG2C6NzWeQTUMUji01EcHkC8o+Pts8ANiNOYcjxEeyhEyzJKgEizblYzMMKzdrOET6QuqWo3C83K+5+5dsjDn1ooKGRwj3HvgsYcFrQl9NojgQFjoobwsiE/7A+OJhLpBcy/nSVgnoJaMfrO+JsnukZPztbntLvOl56+Vra0N8n5NAYhaSayPiv/ayhjVgjfXd1tjMVTOiDknUOwizZuJ1Y3QH94vUtBgp0WBpBSs/xMyTs8CAwEAAaOB2DCB1TAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRQO4WpM5fWwxib49WTuJkfYDbxODCBlQYDVR0jBIGNMIGKgBRQO4WpM5fWwxib49WTuJkfYDbxOKFcpFowWDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFN1YnNwYWNlMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgNDIzNDmCFBSbFIzzOwJlrzbRL1C0h5U0zIi0MA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEACdDAAoaZFCEY5pmfwbKuKrXtO5iE8lWtiCPjCZEUuT6bXRNcqrdnuV/EAfX9WQoXjalPi0eM78zKmbvRGSTUHwWw49RHjFfeJUKvHNeNnFgTXDjEPNhMvh69kHm453lFRmB+kk6yjtXRZaQEwS8Uuo2Ot+krgNbl6oTBZJ0AHH1MtZECDloms1Km7zsK8wAi5i8TVIKkVr5b2VlhrLgFMvzZ5ViAxIMGB6w47yY4QGQB/5Q8ya9hBs9vkn+wubA+yr4j14JXZ7blVKDSTYva65Ea+PqHyrp+Wnmnbw2ObS7iWexiTy1jD3G0R2avDBFjM8Fj5DbfufsE1b0U10RTtg==';
const ALT_TEST_CERT = 'MIIEOTCCAyGgAwIBAgIJAKZgJdKdCdL6MA0GCSqGSIb3DQEBBQUAMHAxCzAJBgNVBAYTAkFVMREwDwYDVQQIEwhWaWN0b3JpYTESMBAGA1UEBxMJTWVsYm91cm5lMSEwHwYDVQQKExhUYWJjb3JwIEhvbGRpbmdzIExpbWl0ZWQxFzAVBgNVBAMTDnN0cy50YWIuY29tLmF1MB4XDTE3MDUzMDA4NTQwOFoXDTI3MDUyODA4NTQwOFowcDELMAkGA1UEBhMCQVUxETAPBgNVBAgTCFZpY3RvcmlhMRIwEAYDVQQHEwlNZWxib3VybmUxITAfBgNVBAoTGFRhYmNvcnAgSG9sZGluZ3MgTGltaXRlZDEXMBUGA1UEAxMOc3RzLnRhYi5jb20uYXUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD0NuMcflq3rtupKYDf4a7lWmsXy66fYe9n8jB2DuLMakEJBlzn9j6B98IZftrilTq21VR7wUXROxG8BkN8IHY+l8X7lATmD28fFdZJj0c8Qk82eoq48faemth4fBMx2YrpnhU00jeXeP8dIIaJTPCHBTNgZltMMhphklN1YEPlzefJs3YD+Ryczy1JHbwETxt+BzO1JdjBe1fUTyl6KxAwWvtsNBURmQRYlDOk4GRgdkQnfxBuCpOMeOpV8wiBAi3h65Lab9C5avu4AJlA9e4qbOmWt6otQmgy5fiJVy6bH/d8uW7FJmSmePX9sqAWa9szhjdn36HHVQsfHC+IUEX7AgMBAAGjgdUwgdIwHQYDVR0OBBYEFN6z6cuxY7FTkg1S/lIjnS4x5ARWMIGiBgNVHSMEgZowgZeAFN6z6cuxY7FTkg1S/lIjnS4x5ARWoXSkcjBwMQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExEjAQBgNVBAcTCU1lbGJvdXJuZTEhMB8GA1UEChMYVGFiY29ycCBIb2xkaW5ncyBMaW1pdGVkMRcwFQYDVQQDEw5zdHMudGFiLmNvbS5hdYIJAKZgJdKdCdL6MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAMi5HyvXgRa4+kKz3dk4SwAEXzeZRcsbeDJWVUxdb6a+JQxIoG7L9rSbd6yZvP/Xel5TrcwpCpl5eikzXB02/C0wZKWicNmDEBlOfw0Pc5ngdoh6ntxHIWm5QMlAfjR0dgTlojN4Msw2qk7cP1QEkV96e2BJUaqaNnM3zMvd7cfRjPNfbsbwl6hCCCAdwrALKYtBnjKVrCGPwO+xiw5mUJhZ1n6ZivTOdQEWbl26UO60J9ItiWP8VK0d0aChn326Ovt7qC4S3AgDlaJwcKe5Ifxl/UOWePGRwXj2UUuDWFhjtVmRntMmNZbe5yE8MkEvU+4/c6LqGwTCgDenRbK53Dg=';

describe( 'node-saml /', function() {

  describe( 'saml.js / ', function() {
    it( 'should throw an error if cert property is provided to saml constructor but is empty', function() {
      should(function() {
        new SAML( { cert: null } );
      }).throw('Invalid property: cert must not be empty');
    });

    it( '_generateUniqueID should generate 20 char IDs', function() {
      var samlObj = new SAML( { entryPoint: 'foo' } );
      for(var i = 0; i < 200; i++){
        samlObj._generateUniqueID().length.should.eql(20);
      }
    });

    it( '_generateLogoutRequest', function( done ) {
      var expectedRequest = {
        'samlp:LogoutRequest':
        { '$':
        { 'xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        //ID: '_85ba0a112df1ffb57805',
        Version: '2.0',
        //IssueInstant: '2014-05-29T03:32:23Z',
        Destination: 'foo' },
        'saml:Issuer':
        [ { _: 'onelogin_saml',
        '$': { 'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion' } } ],
        'saml:NameID': [ { _: 'bar', '$': { Format: 'foo' } } ] }
      };

      var samlObj = new SAML( { entryPoint: 'foo' } );
      var logoutRequestPromise = samlObj._generateLogoutRequest({
        nameIDFormat: 'foo',
        nameID: 'bar'
      });

      logoutRequestPromise.then(function(logoutRequest) {
        parseString( logoutRequest, function( err, doc ) {
          try {
            delete doc['samlp:LogoutRequest']['$']['ID'];
            delete doc['samlp:LogoutRequest']['$']['IssueInstant'];
            doc.should.eql( expectedRequest );
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
    });

    it( '_generateLogoutRequest adds the NameQualifier and SPNameQualifier to the saml request', function( done ) {
      var expectedRequest = {
        'samlp:LogoutRequest':
        { '$':
        { 'xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        //ID: '_85ba0a112df1ffb57805',
        Version: '2.0',
        //IssueInstant: '2014-05-29T03:32:23Z',
        Destination: 'foo' },
        'saml:Issuer':
        [ { _: 'onelogin_saml',
        '$': { 'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion' } } ],
        'saml:NameID': [ { _: 'bar', '$': { Format: 'foo',
        SPNameQualifier: 'Service Provider',
        NameQualifier: 'Identity Provider' } } ] }
      };

      var samlObj = new SAML( { entryPoint: 'foo' } );
      var logoutRequestPromise = samlObj._generateLogoutRequest({
        nameIDFormat: 'foo',
        nameID: 'bar',
        nameQualifier: 'Identity Provider',
        spNameQualifier: 'Service Provider'
      });

      logoutRequestPromise.then(function(logoutRequest) {
        parseString( logoutRequest, function( err, doc ) {
          try {
            delete doc['samlp:LogoutRequest']['$']['ID'];
            delete doc['samlp:LogoutRequest']['$']['IssueInstant'];
            doc.should.eql( expectedRequest );
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
    });

    it( '_generateLogoutResponse', function( done ) {
      var expectedResponse =  {
        'samlp:LogoutResponse':
        { '$':
        { 'xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        //ID: '_d11b3c5e085b2417f4aa',
        Version: '2.0',
        //IssueInstant: '2014-05-29T01:11:32Z',
        Destination: 'foo',
        InResponseTo: 'quux' },
        'saml:Issuer': [ 'onelogin_saml' ],
        'samlp:Status': [ { 'samlp:StatusCode': [ { '$': { Value: 'urn:oasis:names:tc:SAML:2.0:status:Success' } } ] } ] }
      };

      var samlObj = new SAML( { entryPoint: 'foo' } );
      var logoutRequest = samlObj._generateLogoutResponse({}, { ID: 'quux' });
      parseString( logoutRequest, function( err, doc ) {
        try {
          delete doc['samlp:LogoutResponse']['$']['ID'];
          delete doc['samlp:LogoutResponse']['$']['IssueInstant'];
          doc.should.eql( expectedResponse );
          done();
        } catch (err2) {
          done(err2);
        }
      });
    });

    it( '_generateLogoutRequest', function( done ) {
      var expectedRequest = {
        'samlp:LogoutRequest':
        { '$':
        { 'xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        //ID: '_85ba0a112df1ffb57805',
        Version: '2.0',
        //IssueInstant: '2014-05-29T03:32:23Z',
        Destination: 'foo' },
        'saml:Issuer':
        [ { _: 'onelogin_saml',
        '$': { 'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion' } } ],
        'saml:NameID': [ { _: 'bar', '$': { Format: 'foo' } } ],
        'saml2p:SessionIndex':
        [ { _: 'session-id',
        '$': { 'xmlns:saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol' } } ] }
      };

      var samlObj = new SAML( { entryPoint: 'foo' } );
      var logoutRequestPromise = samlObj._generateLogoutRequest({
        nameIDFormat: 'foo',
        nameID: 'bar',
        sessionIndex: 'session-id'
      });

      logoutRequestPromise.then(function(logoutRequest) {
        parseString( logoutRequest, function( err, doc ) {
          try {
            delete doc['samlp:LogoutRequest']['$']['ID'];
            delete doc['samlp:LogoutRequest']['$']['IssueInstant'];
            doc.should.eql( expectedRequest );
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
    });

    it( '_generateLogoutRequest saves id and instant to cache', function( done ) {
      var samlObj = new SAML( { entryPoint: 'foo' } );
      var cacheSaveSpy = sinon.spy(samlObj.cacheProvider, 'save');
      var logoutRequestPromise = samlObj._generateLogoutRequest({
        nameIDFormat: 'foo',
        nameID: 'bar',
        sessionIndex: 'session-id'
      });

      logoutRequestPromise.then(function(logoutRequest) {
        parseString( logoutRequest, function( err, doc ) {
          try {
            var id = doc['samlp:LogoutRequest']['$']['ID'];
            var issueInstant = doc['samlp:LogoutRequest']['$']['IssueInstant'];

            id.should.be.an.instanceOf(String);
            issueInstant.should.be.an.instanceOf(String);
            cacheSaveSpy.called.should.eql(true);
            cacheSaveSpy.calledWith(id, issueInstant).should.eql(true);
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
    });

    describe( 'generateServiceProviderMetadata tests /', function() {
      function testMetadata( samlConfig, expectedMetadata, signingCert ) {
        var samlObj = new SAML( samlConfig );
        var decryptionCert = fs.readFileSync(__dirname + '/static/testshib encryption cert.pem', 'utf-8');
        var metadata = samlObj.generateServiceProviderMetadata( decryptionCert, signingCert );
        // splits are to get a nice diff if they don't match for some reason
        metadata.split( '\n' ).should.eql( expectedMetadata.split( '\n' ) );
      }

      it( 'config with callbackUrl and decryptionPvk should pass', function() {
        var samlConfig = {
          issuer: 'http://example.serviceprovider.com',
          callbackUrl: 'http://example.serviceprovider.com/saml/callback',
          identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
          decryptionPvk: fs.readFileSync(__dirname + '/static/testshib encryption pvk.pem')
        };
        var expectedMetadata = fs.readFileSync(__dirname + '/static/expected metadata.xml', 'utf-8');

        testMetadata( samlConfig, expectedMetadata );
      });

      it( 'config with callbackUrl should pass', function() {
        var samlConfig = {
          issuer: 'http://example.serviceprovider.com',
          callbackUrl: 'http://example.serviceprovider.com/saml/callback',
          identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
        };
        var expectedMetadata = fs.readFileSync(__dirname + '/static/expected metadata without key.xml', 'utf-8');

        testMetadata( samlConfig, expectedMetadata );
      });

      it( 'config with protocol, path, host, and decryptionPvk should pass', function() {
        var samlConfig = {
          issuer: 'http://example.serviceprovider.com',
          protocol: 'http://',
          host: 'example.serviceprovider.com',
          path: '/saml/callback',
          identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
          decryptionPvk: fs.readFileSync(__dirname + '/static/testshib encryption pvk.pem')
        };
        var expectedMetadata = fs.readFileSync(__dirname + '/static/expected metadata.xml', 'utf-8');

        testMetadata( samlConfig, expectedMetadata );
      });

      it( 'config with protocol, path, and host should pass', function() {
        var samlConfig = {
          issuer: 'http://example.serviceprovider.com',
          protocol: 'http://',
          host: 'example.serviceprovider.com',
          path: '/saml/callback',
          identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
        };
        var expectedMetadata = fs.readFileSync(__dirname + '/static/expected metadata without key.xml', 'utf-8');

        testMetadata( samlConfig, expectedMetadata );
      });

      it( 'config with protocol, path, host, decryptionPvk and privateCert should pass', function() {
        var samlConfig = {
          issuer: 'http://example.serviceprovider.com',
          protocol: 'http://',
          host: 'example.serviceprovider.com',
          path: '/saml/callback',
          identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
          decryptionPvk: fs.readFileSync(__dirname + '/static/testshib encryption pvk.pem'),
          privateCert: fs.readFileSync(__dirname + '/static/acme_tools_com.key')
        };
        var expectedMetadata = fs.readFileSync(__dirname + '/static/expectedMetadataWithBothKeys.xml', 'utf-8');
        var signingCert = fs.readFileSync(__dirname + '/static/acme_tools_com.cert').toString();

        testMetadata( samlConfig, expectedMetadata, signingCert );
      });

    });

    it('generateServiceProviderMetadata contains logout callback url', function () {
      var samlConfig = {
        issuer: 'http://example.serviceprovider.com',
        callbackUrl: 'http://example.serviceprovider.com/saml/callback',
        identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        decryptionPvk: fs.readFileSync(__dirname + '/static/testshib encryption pvk.pem'),
        logoutCallbackUrl: 'http://example.serviceprovider.com/logout'
      };

      var samlObj = new SAML(samlConfig);
      var decryptionCert = fs.readFileSync(__dirname + '/static/testshib encryption cert.pem', 'utf-8');
      var metadata = samlObj.generateServiceProviderMetadata(decryptionCert);
      metadata.should.containEql('SingleLogoutService');
      metadata.should.containEql(samlConfig.logoutCallbackUrl);
    });

    it('_certToPEM should generate valid certificate', function(done){
      var samlConfig = {
        entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
        cert: '-----BEGIN CERTIFICATE-----'+TEST_CERT+'-----END CERTIFICATE-----',
        acceptedClockSkewMs: -1
      };
      var samlObj = new SAML( samlConfig );
      var certificate = samlObj._certToPEM(samlConfig.cert);

      if (certificate.match(/BEGIN/g).length == 1
      && certificate.match(/END/g).length == 1){
        done();
      } else {
        done('Certificate should have only 1 BEGIN and 1 END block');
      }
    });

    describe('validatePostResponse checks /', function() {
      it('response with junk content should explain the XML or base64 is not valid', async function() {
        var samlObj = new SAML( { cert: TEST_CERT });

        samlObj.validatePostResponse({SAMLResponse: 'BOOM'}).should.be.rejectedWith(/SAMLResponse is not valid base64-encoded XML/);
      });
      it('response with error status message should generate appropriate error', async function() {
        var xml = '<?xml version="1.0" encoding="UTF-8"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://localhost/browserSamlLogin" ID="_6a377272c8662561acf1056274ef3f81" InResponseTo="_4324fb0d00661146f7dc" IssueInstant="2014-07-02T18:16:31.278Z" Version="2.0"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://idp.testshib.org/idp/shibboleth</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"/></saml2p:StatusCode><saml2p:StatusMessage>Required NameID format not supported</saml2p:StatusMessage></saml2p:Status></saml2p:Response>';
        var base64xml = Buffer.from( xml ).toString('base64');
        var container = { SAMLResponse: base64xml };
        var samlObj = new SAML( {
          cert: '-----BEGIN CERTIFICATE-----'+TEST_CERT+'-----END CERTIFICATE-----',
        });

        await samlObj.validatePostResponse( container ).should.be.rejectedWith(/Responder/);
        await samlObj.validatePostResponse( container ).should.be.rejectedWith(/Required NameID format not supported/);
        await samlObj.validatePostResponse( container ).catch(err => should.exist( err.statusXml ));

      });

      it('response with error status code should generate appropriate error', async function() {
        var xml = '<?xml version="1.0" encoding="UTF-8"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://localhost/browserSamlLogin" ID="_6a377272c8662561acf1056274ef3f81" InResponseTo="_4324fb0d00661146f7dc" IssueInstant="2014-07-02T18:16:31.278Z" Version="2.0"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://idp.testshib.org/idp/shibboleth</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"/></saml2p:StatusCode></saml2p:Status></saml2p:Response>';
        var base64xml = Buffer.from( xml ).toString('base64');
        var container = { SAMLResponse: base64xml };
        var samlObj = new SAML( {} );

        await samlObj.validatePostResponse( container ).should.be.rejectedWith(/Responder/);
        await samlObj.validatePostResponse( container ).should.be.rejectedWith(/InvalidNameIDPolicy/);
        await samlObj.validatePostResponse( container ).catch(err => should.exist( err.statusXml ));
      });

      it('accept response with an attributeStatement element without attributeValue', async function() {
        var fakeClock = sinon.useFakeTimers(Date.parse('2015-08-31T08:55:00+00:00'));
        var container = {
          SAMLResponse: fs.readFileSync(
            __dirname + '/static/response-with-uncomplete-attribute.xml'
            ).toString('base64')
        };
        var samlObj = new SAML();

        const {profile} = await samlObj.validatePostResponse(container);
        profile.issuer.should.eql('https://evil-corp.com');
        profile.nameID.should.eql('vincent.vega@evil-corp.com');
        should(profile).have.property('evil-corp.egroupid').eql('vincent.vega@evil-corp.com');
        // attributes without attributeValue child should be ignored
        should(profile).not.have.property('evilcorp.roles');

        fakeClock.restore();
      });

      it('removes InResponseTo value if response validation fails', async function() {
        var requestId = '_a6fc46be84e1e3cf3c50';
        var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
        '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+TEST_CERT+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ben@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
        '</samlp:Response>';
        var base64xml = Buffer.from( xml ).toString('base64');
        var container = { SAMLResponse: base64xml };
        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
          cert: TEST_CERT,
          validateInResponseTo: true
        };
        var samlObj = new SAML( samlConfig );

        // Mock the SAML request being passed through Passport-SAML
        await samlObj.cacheProvider.save(requestId, new Date().toISOString());


        await samlObj.validatePostResponse( container ).should.be.rejectedWith({message: 'Invalid signature'});
        await samlObj.validatePostResponse( container ).should.be.rejectedWith({message: 'InResponseTo is not valid'});
      });

      describe( 'validatePostResponse xml signature checks /', function() {

        var fakeClock;
        beforeEach(function(){
          fakeClock = sinon.useFakeTimers(Date.parse('2014-05-28T00:13:09Z'));
        });
        afterEach(function(){
          fakeClock.restore();
        });

        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
          cert: TEST_CERT,
        };
        it( 'valid onelogin xml document should validate', async function( ) {
          var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+TEST_CERT+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            '</samlp:Response>';
          var base64xml = Buffer.from( xml ).toString('base64');
          var container = { SAMLResponse: base64xml };
          var samlObj = new SAML( samlConfig );

          const {profile} = await samlObj.validatePostResponse( container );
          profile.nameID.should.startWith( 'ploer' );
        });

        it( 'onelogin xml document with altered assertion should fail', async function() {
          var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+TEST_CERT+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ben@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            '</samlp:Response>';
          var base64xml = Buffer.from( xml ).toString('base64');
          var container = { SAMLResponse: base64xml };
          var samlObj = new SAML( samlConfig );

          await samlObj.validatePostResponse( container ).should.be.rejectedWith(/Invalid signature/);
        });

        it( 'onelogin xml document with duplicate altered assertion should fail', async function() {
          var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+TEST_CERT+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+TEST_CERT+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ben@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            '</samlp:Response>';
          var base64xml = Buffer.from( xml ).toString('base64');
          var container = { SAMLResponse: base64xml };
          var samlObj = new SAML( samlConfig );

          await samlObj.validatePostResponse( container ).should.be.rejectedWith(/Invalid signature/);
        });

        it( 'onelogin xml document with extra unsigned & altered assertion should fail', async function() {
          var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efab" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ben@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+TEST_CERT+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            '</samlp:Response>';
          var base64xml = Buffer.from( xml ).toString('base64');
          var container = { SAMLResponse: base64xml };
          var samlObj = new SAML( samlConfig );

          await samlObj.validatePostResponse( container ).should.be.rejectedWith(/Invalid signature/);
        });

        it( 'onelogin xml document with extra nexted assertion should fail', async function() {
          var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+TEST_CERT+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo>' +
            '<ds:Object>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            '</ds:Object>' +
            '</ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            '</samlp:Response>';
          var base64xml = Buffer.from( xml ).toString('base64');
          var container = { SAMLResponse: base64xml };
          var samlObj = new SAML( samlConfig );

          await samlObj.validatePostResponse( container ).should.be.rejectedWith(/Invalid signature/);
        });

        it( 'multiple certs should validate with one of the certs', async function() {
          var multiCertSamlConfig = {
            entryPoint: samlConfig.entryPoint,
            cert: [
              ALT_TEST_CERT,
              samlConfig.cert
            ]
          };
          var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' + TEST_CERT + '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            '</samlp:Response>';
          var base64xml = Buffer.from( xml ).toString('base64');
          var container = { SAMLResponse: base64xml };
          var samlObj = new SAML( multiCertSamlConfig );
          const {profile} = await samlObj.validatePostResponse( container );
          profile.nameID.should.startWith( 'ploer' );
        });

        it( 'cert as a function should validate with the returned cert', async function() {
          var functionCertSamlConfig = {
            entryPoint: samlConfig.entryPoint,
            cert: function (callback) { callback(null, samlConfig.cert); }
          };
          var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
            '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' + TEST_CERT + '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
            '</samlp:Response>';
          var base64xml = Buffer.from( xml ).toString('base64');
          var container = { SAMLResponse: base64xml };
          var samlObj = new SAML( functionCertSamlConfig );
          const {profile} = await samlObj.validatePostResponse( container );

          profile.nameID.should.startWith( 'ploer' );
        });

        it( 'cert as a function should validate with one of the returned certs', async function() {
          var functionMultiCertSamlConfig = {
            entryPoint: samlConfig.entryPoint,
            cert: function (callback) {
              callback(null, [
                ALT_TEST_CERT,
                samlConfig.cert
              ]);
            }
          };
          var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
          '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' + TEST_CERT + '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
          '</samlp:Response>';
          var base64xml = Buffer.from( xml ).toString('base64');
          var container = { SAMLResponse: base64xml };
          var samlObj = new SAML( functionMultiCertSamlConfig );
          const {profile} = await samlObj.validatePostResponse( container );
          profile.nameID.should.startWith( 'ploer' );
        });

        it( 'cert as a function should return an error if the cert function returns an error', async function() {
          var errorToReturn = new Error('test');
          var functionErrorCertSamlConfig = {
            entryPoint: samlConfig.entryPoint,
            cert: function (callback) { callback(errorToReturn); }
          };
          var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
          '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' + TEST_CERT + '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
          '</samlp:Response>';
          var base64xml = Buffer.from( xml ).toString('base64');
          var container = { SAMLResponse: base64xml };
          var samlObj = new SAML( functionErrorCertSamlConfig );

          await samlObj.validatePostResponse( container ).should.be.rejectedWith(errorToReturn);
        });
      });
    });

    describe( 'getAuthorizeUrl request RelayState checks /', function() {
      var fakeClock;
      beforeEach(function(){
        fakeClock = sinon.useFakeTimers(Date.parse('2014-05-28T00:13:09Z'));
      });
      afterEach(function(){
        fakeClock.restore();
      });

      it ( 'should not pass RelayState by default', async function() {
        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
        };
        var samlObj = new SAML( samlConfig );
        samlObj._generateUniqueID = function () { return '12345678901234567890'; };
        const url = await samlObj.getAuthorizeUrl({}, {});

        var searchParams = new URL(url).searchParams;
        should.not.exist(searchParams.get('RelayState'));
      });

      it ( 'should pass through RelayState', async function() {
        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
        };
        var samlObj = new SAML( samlConfig );
        samlObj._generateUniqueID = function () { return '12345678901234567890'; };
        const url = await samlObj.getAuthorizeUrl({RelayState: 'test'}, {});

        var searchParams = new URL(url).searchParams;
        searchParams.get('RelayState').should.match('test');
      });
    });

    describe( 'getAuthorizeUrl request signature checks /', function() {
      var fakeClock;
      beforeEach(function(){
        fakeClock = sinon.useFakeTimers(Date.parse('2014-05-28T00:13:09Z'));
      });
      afterEach(function(){
        fakeClock.restore();
      });

      it( 'acme_tools request signed with sha256', async function() {
        var samlConfig = {
          entryPoint: 'https://adfs.acme_tools.com/adfs/ls/',
          issuer: 'acme_tools_com',
          callbackUrl: 'https://relyingparty/adfs/postResponse',
          privateCert: fs.readFileSync(__dirname + '/static/acme_tools_com.key', 'utf-8'),
          authnContext: 'http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password',
          identifierFormat: null,
          signatureAlgorithm: 'sha256',
          additionalParams: {
            customQueryStringParam: 'CustomQueryStringParamValue'
          }
        };
        var samlObj = new SAML( samlConfig );
        samlObj._generateUniqueID = function () { return '12345678901234567890'; };
        const url = await samlObj.getAuthorizeUrl({}, {});

        var searchParams = new URL(url).searchParams;
        searchParams.get('SigAlg').should.match('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
        searchParams.get('Signature').should.match('hel9NaoLU0brY/VhrQsY+lTtuAbTsT/ul6nZ/eVlSMXQRaKn5LTbKadzxmPghX7s4xoHwdah+yZHK/0u4StYSj4b5MKcqbsJapVr2R7H90z8YfGfR2C/G0Gng721YV9Da6VBzKg8Was91zQotgsMpZ9pGX1kPKi6cgFwPwM4NEFugn8AYgXEriNvO5+Q23K/MdBT2bgwRTj2FQCWTuQcgwbyWHXoquHztZ0lbh8UhY5BfQRv7c6D9XPkQEMMQFQeME4PIEg3JnynwFZk5wwhkphMd5nXxau+zt7Nfp4fRm0G8WYnxV1etBnWimwSglZVaSHFYeQBRsC2wvKSiVS8JA==');
        searchParams.get('customQueryStringParam').should.match('CustomQueryStringParamValue');
      });

      it( 'acme_tools request not signed if missing entry point', async function() {
        var samlConfig = {
          entryPoint: '',
          issuer: 'acme_tools_com',
          callbackUrl: 'https://relyingparty/adfs/postResponse',
          privateCert: fs.readFileSync(__dirname + '/static/acme_tools_com.key', 'utf-8'),
          authnContext: 'http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password',
          signatureAlgorithm: 'sha256',
          additionalParams: {
            customQueryStringParam: 'CustomQueryStringParamValue'
          }
        };
        var samlObj = new SAML( samlConfig );
        samlObj._generateUniqueID = function () { return '12345678901234567890'; };

        var request = '<?xml version=\\"1.0\\"?><samlp:AuthnRequest xmlns:samlp=\\"urn:oasis:names:tc:SAML:2.0:protocol\\" ID=\\"_ea40a8ab177df048d645\\" Version=\\"2.0\\" IssueInstant=\\"2017-08-22T19:30:01.363Z\\" ProtocolBinding=\\"urn:oasis:names$tc:SAML:2.0:bindings:HTTP-POST\\" AssertionConsumerServiceURL=\\"https://example.com/login/callback\\" Destination=\\"https://www.example.com\\"><saml:Issuer xmlns:saml=\\"urn:oasis:names:tc:SAML:2.0:assertion\\">onelogin_saml</saml:Issuer><s$mlp:NameIDPolicy xmlns:samlp=\\"urn:oasis:names:tc:SAML:2.0:protocol\\" Format=\\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\\" AllowCreate=\\"true\\"/><samlp:RequestedAuthnContext xmlns:samlp=\\"urn:oasis:names:tc:SAML:2.0:protoc$l\\" Comparison=\\"exact\\"><saml:AuthnContextClassRef xmlns:saml=\\"urn:oasis:names:tc:SAML:2.0:assertion\\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp$AuthnRequest>';
        await samlObj._requestToUrl(request, null, 'authorize', {}).should.be.rejectedWith({message: '"entryPoint" config parameter is required for signed messages'});
      });

      it( 'acme_tools request signed with sha1', async function() {
        var samlConfig = {
          entryPoint: 'https://adfs.acme_tools.com/adfs/ls/',
          issuer: 'acme_tools_com',
          callbackUrl: 'https://relyingparty/adfs/postResponse',
          privateCert: fs.readFileSync(__dirname + '/static/acme_tools_com.key', 'utf-8'),
          authnContext: 'http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password',
          identifierFormat: null,
          signatureAlgorithm: 'sha1',
          additionalParams: {
            customQueryStringParam: 'CustomQueryStringParamValue'
          }
        };
        var samlObj = new SAML( samlConfig );
        samlObj._generateUniqueID = function () { return '12345678901234567890'; };
        const url = await samlObj.getAuthorizeUrl({}, {});

        var searchParams = new URL(url).searchParams;
        searchParams.get('SigAlg').should.match('http://www.w3.org/2000/09/xmldsig#rsa-sha1');
        searchParams.get('Signature').should.match('MeFo+LjufxP5A+sCRwzR/YH/RV6W14aYSFjUdie62JxkI6hDcVhoSZQUJ3wtWMhL59gJj05tTFnXAZRqUQVsavyy41cmUZVeCsat0gaHBQOILXpp9deB0iSJt1EVQTOJkVx8uu2/WYu/bBiH7w2bpwuCf1gJhlqZb/ca3B6yjHSMjnnVfc2LbNPWHpE5464lrs79VjDXf9GQWfrBr95dh3P51IAb7C+77KDWQUl9WfZfyyuEgS83vyZ0UGOxT4AObJ6NOcLs8+iidDdWJJkBaKQev6U+AghCjLQUYOrflivLIIyqATKu2q9PbOse6Phmnxok50+broXSG23+e+742Q==');
        searchParams.get('customQueryStringParam').should.match('CustomQueryStringParamValue');
      });
    });

    describe( '_getAdditionalParams checks /', function() {
      it ( 'should not pass any additional params by default', function() {
        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
        };
        var samlObj = new SAML( samlConfig );

        ['logout', 'authorize'].forEach( function( operation ) {
          var additionalParams = samlObj._getAdditionalParams(null, operation);
          additionalParams.should.be.empty;
        });
      });

      it ( 'should not pass any additional params by default apart from the RelayState', function() {
        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
        };
        var samlObj = new SAML( samlConfig );

        ['logout', 'authorize'].forEach( function( operation ) {
          var additionalParams = samlObj._getAdditionalParams('test', operation);

          Object.keys(additionalParams).should.have.length(1);
          additionalParams.should.containEql({'RelayState': 'test'});
        });
      });

      it ( 'should pass additional params with all operations if set in additionalParams', function() {
        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
          additionalParams: {
            'queryParam': 'queryParamValue'
          }
        };
        var samlObj = new SAML( samlConfig );

        ['logout', 'authorize'].forEach( function( operation ) {
          var additionalParams = samlObj._getAdditionalParams(null, operation);
          Object.keys(additionalParams).should.have.length(1);
          additionalParams.should.containEql({'queryParam': 'queryParamValue'});
        });
      });

      it ( 'should pass additional params with "authorize" operations if set in additionalAuthorizeParams', function() {
        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
          additionalAuthorizeParams: {
            'queryParam': 'queryParamValue'
          }
        };
        var samlObj = new SAML( samlConfig );

        var additionalAuthorizeParams = samlObj._getAdditionalParams(null, 'authorize');
        Object.keys(additionalAuthorizeParams).should.have.length(1);
        additionalAuthorizeParams.should.containEql({'queryParam': 'queryParamValue'});

        var additionalLogoutParams = samlObj._getAdditionalParams(null, 'logout');
        additionalLogoutParams.should.be.empty;
      });

      it ( 'should pass additional params with "logout" operations if set in additionalLogoutParams', function() {
        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
          additionalLogoutParams: {
            'queryParam': 'queryParamValue'
          }
        };
        var samlObj = new SAML( samlConfig );

        var additionalAuthorizeParams = samlObj._getAdditionalParams(null, 'authorize');
        additionalAuthorizeParams.should.be.empty;

        var additionalLogoutParams = samlObj._getAdditionalParams(null, 'logout');
        Object.keys(additionalLogoutParams).should.have.length(1);
        additionalLogoutParams.should.containEql({'queryParam': 'queryParamValue'});
      });

      it ( 'should merge additionalLogoutParams and additionalAuthorizeParams with additionalParams', function() {
        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
          additionalParams: {
            'queryParam1': 'queryParamValue'
          },
          additionalAuthorizeParams: {
            'queryParam2': 'queryParamValueAuthorize'
          },
          additionalLogoutParams: {
            'queryParam2': 'queryParamValueLogout'
          }
        };
        var samlObj = new SAML( samlConfig );

        var additionalAuthorizeParams = samlObj._getAdditionalParams(null, 'authorize');
        Object.keys(additionalAuthorizeParams).should.have.length(2);
        additionalAuthorizeParams.should.containEql({'queryParam1': 'queryParamValue', 'queryParam2': 'queryParamValueAuthorize'});

        var additionalLogoutParams = samlObj._getAdditionalParams(null, 'logout');
        Object.keys(additionalLogoutParams).should.have.length(2);
        additionalLogoutParams.should.containEql({'queryParam1': 'queryParamValue', 'queryParam2': 'queryParamValueLogout'});
      });

      it ( 'should merge run-time params additionalLogoutParams and additionalAuthorizeParams with additionalParams', function() {
        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
          additionalParams: {
            'queryParam1': 'queryParamValue'
          },
          additionalAuthorizeParams: {
            'queryParam2': 'queryParamValueAuthorize'
          },
          additionalLogoutParams: {
            'queryParam2': 'queryParamValueLogout'
          }
        };
        var samlObj = new SAML( samlConfig );
        var options = {
          additionalParams: {
            queryParam3: 'queryParamRuntimeValue'
          }
        };

        var additionalAuthorizeParams = samlObj._getAdditionalParams(null, 'authorize', options.additionalParams);
        Object.keys(additionalAuthorizeParams).should.have.length(3);
        additionalAuthorizeParams.should.containEql({'queryParam1': 'queryParamValue',
        'queryParam2': 'queryParamValueAuthorize',
        'queryParam3': 'queryParamRuntimeValue'});

        var additionalLogoutParams = samlObj._getAdditionalParams(null, 'logout', options.additionalParams);
        Object.keys(additionalLogoutParams).should.have.length(3);
        additionalLogoutParams.should.containEql({'queryParam1': 'queryParamValue',
        'queryParam2': 'queryParamValueLogout',
        'queryParam3': 'queryParamRuntimeValue'});
      });

      it ( 'should prioritize additionalLogoutParams and additionalAuthorizeParams over additionalParams', function() {
        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
          additionalParams: {
            'queryParam': 'queryParamValue'
          },
          additionalAuthorizeParams: {
            'queryParam': 'queryParamValueAuthorize'
          },
          additionalLogoutParams: {
            'queryParam': 'queryParamValueLogout'
          }
        };
        var samlObj = new SAML( samlConfig );

        var additionalAuthorizeParams = samlObj._getAdditionalParams(null, 'authorize');
        Object.keys(additionalAuthorizeParams).should.have.length(1);
        additionalAuthorizeParams.should.containEql({'queryParam': 'queryParamValueAuthorize'});

        var additionalLogoutParams = samlObj._getAdditionalParams(null, 'logout');
        Object.keys(additionalLogoutParams).should.have.length(1);
        additionalLogoutParams.should.containEql({'queryParam': 'queryParamValueLogout'});
      });

      it ( 'should prioritize run-time params over all other params', function() {
        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
          additionalParams: {
            'queryParam': 'queryParamValue'
          },
          additionalAuthorizeParams: {
            'queryParam': 'queryParamValueAuthorize'
          },
          additionalLogoutParams: {
            'queryParam': 'queryParamValueLogout'
          }
        };
        var samlObj = new SAML( samlConfig );
        var options = {
          additionalParams: {
            queryParam: 'queryParamRuntimeValue'
          }
        };

        var additionalAuthorizeParams = samlObj._getAdditionalParams(null, 'authorize', options.additionalParams);
        Object.keys(additionalAuthorizeParams).should.have.length(1);
        additionalAuthorizeParams.should.containEql({'queryParam': 'queryParamRuntimeValue'});

        var additionalLogoutParams = samlObj._getAdditionalParams(null, 'logout', options.additionalParams);
        Object.keys(additionalLogoutParams).should.have.length(1);
        additionalLogoutParams.should.containEql({'queryParam': 'queryParamRuntimeValue'});
      });

      it('should check the value of the option `RACComparison`', function() {
        var samlObjBadComparisonType = new SAML({ RACComparison: 'bad_value' });
        should.equal(samlObjBadComparisonType.options.RACComparison, 'exact', ['the default value of the option `RACComparison` must be exact']);

        var validComparisonTypes = ['exact','minimum','maximum','better'], samlObjValidComparisonType;
        validComparisonTypes.forEach(function(RACComparison) {
          samlObjValidComparisonType = new SAML( {RACComparison: RACComparison} );
          should.equal(samlObjValidComparisonType.options.RACComparison, RACComparison);
        });
      });
    });

    describe( 'InResponseTo validation checks /', function(){
      var fakeClock = null;

      afterEach(function() {
        if (fakeClock) {
          fakeClock.restore();
          fakeClock = null;
        }
      });

      it( 'onelogin xml document with InResponseTo from request should validate', async function( ) {
        var requestId = '_a6fc46be84e1e3cf3c50';
        var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
        '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+TEST_CERT+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
        '</samlp:Response>';
        var base64xml = Buffer.from( xml ).toString('base64');
        var container = { SAMLResponse: base64xml };

        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
          cert: TEST_CERT,
          validateInResponseTo: true
        };
        var samlObj = new SAML( samlConfig );

        fakeClock = sinon.useFakeTimers(Date.parse('2014-05-28T00:13:09Z'));

        // Mock the SAML request being passed through Passport-SAML
        await samlObj.cacheProvider.save(requestId, new Date().toISOString());

        const {profile} = await samlObj.validatePostResponse( container );

        profile.nameID.should.startWith( 'ploer' );

        const value = await samlObj.cacheProvider.get(requestId);
        should.not.exist(value);
      });

      it( 'onelogin xml document without InResponseTo from request should fail', async function() {
        var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
        '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+TEST_CERT+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
        '</samlp:Response>';
        var base64xml = Buffer.from( xml ).toString('base64');
        var container = { SAMLResponse: base64xml };

        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
          cert: TEST_CERT,
          validateInResponseTo: true
        };
        var samlObj = new SAML( samlConfig );

        fakeClock = sinon.useFakeTimers(Date.parse('2014-05-28T00:13:09Z'));

        await samlObj.validatePostResponse( container).should.be.rejectedWith({message: 'InResponseTo is not valid'});
      });

      it( 'xml document with SubjectConfirmation InResponseTo from request should be valid', async function(){
        var requestId = '_dfab47d5d46374cd4b71';
        var xml = '<samlp:Response ID="_f6c28a7d-9c82-4ae8-ba14-fc42c85081d3" InResponseTo="_dfab47d5d46374cd4b71" Version="2.0" IssueInstant="2014-06-05T12:07:07.662Z" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">Verizon IDP Hub</saml:Issuer><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" /><Reference URI="#_f6c28a7d-9c82-4ae8-ba14-fc42c85081d3"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><InclusiveNamespaces PrefixList="#default samlp saml ds xs xsi" xmlns="http://www.w3.org/2001/10/xml-exc-c14n#" /></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" /><DigestValue>QecaVjMY/2M4VMJsakvX8uh2Mrg=</DigestValue></Reference></SignedInfo><SignatureValue>QTJ//ZHEQRe9/nA5qTkhECZc2u6M1dHzTkujKBedskLSRPL8LRBb4Yftla0zu848sYvLd3SXzEysYu/jrAjaVDevYZIAdyj/3HCw8pS0ZnQDaCgYuAkH4JmYxBfW1Sc9Kr0vbR58ihwWOZd4xHIn/b8xLs8WNsyTHix2etrLGznioLwTOBO3+SgjwSiSP9NUhrlOvolbuu/6xhLi37/L08JaBvOw3o0k4V8xS87SFczhm4f6wvQM5mP6sZAreoNcWZqQM7vIHFjL0/H9vTaLAN8+fQOc81xFtateTKwFQlJMUmdWKZ8L7ns0Uf1xASQjXtSAACbXI+PuVLjz8nnm3g==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIC7TCCAdmgAwIBAgIQuIdqos+9yKBC4oygbhtdfzAJBgUrDgMCHQUAMBIxEDAOBgNVBAMTB1Rlc3RTVFMwHhcNMTQwNDE2MTIyMTEwWhcNMzkxMjMxMjM1OTU5WjASMRAwDgYDVQQDEwdUZXN0U1RTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmhReamVYbeOWwrrAvHPvS9KKBwv4Tj7wOSGDXbNgfjhSvVyXsnpYRcuoJkvE8b9tCjFTbXCfbhnaVrpoXaWFtP1YvUIZvCJGdOOTXltMNDlNIaFmsIsomza8IyOHXe+3xHWVtxO8FG3qnteSkkVIQuAvBqpPfQtxrXCZOlbQZm7q69QIQ64JvLJfRwHN1EywMBVwbJgrV8gBdE3RITI76coSOK13OBTlGtB0kGKLDrF2JW+5mB+WnFR7GlXUj+V0R9WStBomVipJEwr6Q3fU0deKZ5lLw0+qJ0T6APInwN5TIN/AbFCHd51aaf3zEP+tZacQ9fbZqy9XBAtL2pCAJQIDAQABo0cwRTBDBgNVHQEEPDA6gBDECazhZ8Ar+ULXb0YTs5MvoRQwEjEQMA4GA1UEAxMHVGVzdFNUU4IQuIdqos+9yKBC4oygbhtdfzAJBgUrDgMCHQUAA4IBAQAioMSOU9QFw+yhVxGUNK0p/ghVsHnYdeOE3vSRhmFPsetBt8S35sI4QwnQNiuiEYqp++FabiHgePOiqq5oeY6ekJik1qbs7fgwnaQXsxxSucHvc4BU81x24aKy6jeJzxmFxo3mh6y/OI1peCMSH48iUzmhnoSulp0+oAs3gMEFI0ONbgAA/XoAHaVEsrPj10i3gkztoGdpH0DYUe9rABOJxX/3mNF+dCVJG7t7BoSlNAWlSDErKciNNax1nBskFqNWNIKzUKBIb+GVKkIB2QpATMQB6Oe7inUdT9kkZ/Q7oPBATZk+3mFsIoWr8QRFSqvToOhun7EY2/VtuiV1d932</X509Certificate></X509Data></KeyInfo></Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status><saml:Assertion Version="2.0" ID="_ea67f283-0afb-465a-ba78-5abe7b7f8584" IssueInstant="2014-06-05T12:07:07.663Z" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>Verizon IDP Hub</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">UIS/jochen-work</saml:NameID><saml:SubjectConfirmation><saml:SubjectConfirmationData NotBefore="2014-06-05T12:06:07.664Z" NotOnOrAfter="2014-06-05T12:10:07.664Z" InResponseTo="_dfab47d5d46374cd4b71" /></saml:SubjectConfirmation></saml:Subject><saml:AttributeStatement><saml:Attribute Name="vz::identity" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">UIS/jochen-work</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::subjecttype" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">UIS user</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::account" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">e9aba0c4-ece8-4b44-9526-d24418aa95dc</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::org" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">testorg</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">Test User</saml:AttributeValue></saml:Attribute><saml:Attribute Name="net::ip" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">::1</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
        var base64xml = Buffer.from( xml ).toString('base64');
        var container = { SAMLResponse: base64xml };

        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
          cert: 'MIIC7TCCAdmgAwIBAgIQuIdqos+9yKBC4oygbhtdfzAJBgUrDgMCHQUAMBIxEDAOBgNVBAMTB1Rlc3RTVFMwHhcNMTQwNDE2MTIyMTEwWhcNMzkxMjMxMjM1OTU5WjASMRAwDgYDVQQDEwdUZXN0U1RTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmhReamVYbeOWwrrAvHPvS9KKBwv4Tj7wOSGDXbNgfjhSvVyXsnpYRcuoJkvE8b9tCjFTbXCfbhnaVrpoXaWFtP1YvUIZvCJGdOOTXltMNDlNIaFmsIsomza8IyOHXe+3xHWVtxO8FG3qnteSkkVIQuAvBqpPfQtxrXCZOlbQZm7q69QIQ64JvLJfRwHN1EywMBVwbJgrV8gBdE3RITI76coSOK13OBTlGtB0kGKLDrF2JW+5mB+WnFR7GlXUj+V0R9WStBomVipJEwr6Q3fU0deKZ5lLw0+qJ0T6APInwN5TIN/AbFCHd51aaf3zEP+tZacQ9fbZqy9XBAtL2pCAJQIDAQABo0cwRTBDBgNVHQEEPDA6gBDECazhZ8Ar+ULXb0YTs5MvoRQwEjEQMA4GA1UEAxMHVGVzdFNUU4IQuIdqos+9yKBC4oygbhtdfzAJBgUrDgMCHQUAA4IBAQAioMSOU9QFw+yhVxGUNK0p/ghVsHnYdeOE3vSRhmFPsetBt8S35sI4QwnQNiuiEYqp++FabiHgePOiqq5oeY6ekJik1qbs7fgwnaQXsxxSucHvc4BU81x24aKy6jeJzxmFxo3mh6y/OI1peCMSH48iUzmhnoSulp0+oAs3gMEFI0ONbgAA/XoAHaVEsrPj10i3gkztoGdpH0DYUe9rABOJxX/3mNF+dCVJG7t7BoSlNAWlSDErKciNNax1nBskFqNWNIKzUKBIb+GVKkIB2QpATMQB6Oe7inUdT9kkZ/Q7oPBATZk+3mFsIoWr8QRFSqvToOhun7EY2/VtuiV1d932',
          validateInResponseTo: true
        };
        var samlObj = new SAML( samlConfig );

        fakeClock = sinon.useFakeTimers(Date.parse('2014-06-05T12:07:07.662Z'));

        // Mock the SAML request being passed through Passport-SAML
        await samlObj.cacheProvider.save(requestId, new Date().toISOString());

        const {profile} = await samlObj.validatePostResponse( container );

        profile.nameID.should.startWith( 'UIS/jochen-work' );
        const value = await samlObj.cacheProvider.get(requestId);
        should.not.exist(value);
      });

      it( 'xml document with SubjectConfirmation and missing InResponseTo from request should not be valid', async function(){
        var requestId = '_dfab47d5d46374cd4b71';
        var xml = '<samlp:Response ID="_f6c28a7d-9c82-4ae8-ba14-fc42c85081d3" Version="2.0" IssueInstant="2014-06-05T12:07:07.662Z" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">Verizon IDP Hub</saml:Issuer><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" /><Reference URI="#_f6c28a7d-9c82-4ae8-ba14-fc42c85081d3"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><InclusiveNamespaces PrefixList="#default samlp saml ds xs xsi" xmlns="http://www.w3.org/2001/10/xml-exc-c14n#" /></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" /><DigestValue>c8xR7YMU8KAYbkV7Jx3WEBhIqso=</DigestValue></Reference></SignedInfo><SignatureValue>jPOrsXdG/YVyGrykXYUbgVK7iX+tNFjMJnOA2iFWOjjtWco9M5DT9tyUsYAag4o4oDUEJribGWhCYn6nvQ24zfW+eJYGwbxO0TSZ26J0iuhnxr+MMFmJVGjxArD70dea0kITssqCxJNKUwmTqteAQ73+qk91H9E9IDoOjMwQERoyD4sAtvfJErRrRontvg9xeQ0BFtyMzJZkwU24QqHvoHyw9/dVO8/NFPydwjaI9uZMu6/QUYKKvkbf6VUXXQUHIiZgX0GCudpB908BqWIcj0dWv8oKGGajQWp+d8Jlx/nxbUTAs8vL1f0dxW3LYCZsDExHmjRQTBhM0pQVMT+HlA==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIICrjCCAZYCCQDWybyUsLVkXzANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDFA5hY21lX3Rvb2xzLmNvbTAeFw0xNTA4MTgwODQ3MzZaFw0yNTA4MTcwODQ3MzZaMBkxFzAVBgNVBAMUDmFjbWVfdG9vbHMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlyT+OzEymhaZFNfx4+HFxZbBP3egvcUgPvGa7wWCV7vyuCauLBqwO1FQqzaRDxkEihkHqmUz63D25v2QixLxXyqaFQ8TxDFKwYATtSL7x5G2Gww56H0L1XGgYdNW1akPx90P+USmVn1Wb//7AwU+TV+u4jIgKZyTaIFWdFlwBhlp4OBEHCyYwngFgMyVoCBsSmwb4if7Mi5T746J9ZMQpC+ts+kfzley59Nz55pa5fRLwu4qxFUv2oRdXAf2ZLuxB7DPQbRH82/ewZZ8N4BUGiQyAwOsHgp0sb9JJ8uEM/qhyS1dXXxjo+kxsI5HXhxp4P5R9VADuOquaLIo8ptIrQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBW/Y7leJnV76+6bzeqqi+buTLyWc1mASi5LVH68mdailg2WmGfKlSMLGzFkNtg8fJnfaRZ/GtxmSxhpQRHn63ZlyzqVrFcJa0qzPG21PXPHG/ny8pN+BV8fk74CIb/+YN7NvDUrV7jlsPxNT2rQk8G2fM7jsTMYvtz0MBkrZZsUzTv4rZkF/v44J/ACDirKJiE+TYArm70yQPweX6RvYHNZLSzgg4o+hoyBXo5BGQetAjmcIhC6ZOwN3iVhGjp0YpWM0pkqStPy3sIR0//LZbskWWlSRb0fX1c4632Xb+zikfec4DniYV6CxkB2U+plHpOX1rt1R+UiTEIhTSXPNt/</X509Certificate></X509Data></KeyInfo></Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status><saml:Assertion Version="2.0" ID="_ea67f283-0afb-465a-ba78-5abe7b7f8584" IssueInstant="2014-06-05T12:07:07.663Z" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>Verizon IDP Hub</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">UIS/jochen-work</saml:NameID><saml:SubjectConfirmation><saml:SubjectConfirmationData NotBefore="2014-06-05T12:06:07.664Z" NotOnOrAfter="2014-06-05T12:10:07.664Z" /></saml:SubjectConfirmation></saml:Subject><saml:AttributeStatement><saml:Attribute Name="vz::identity" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">UIS/jochen-work</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::subjecttype" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">UIS user</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::account" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">e9aba0c4-ece8-4b44-9526-d24418aa95dc</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::org" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">testorg</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">Test User</saml:AttributeValue></saml:Attribute><saml:Attribute Name="net::ip" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">::1</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
        var base64xml = Buffer.from( xml ).toString('base64');
        var container = { SAMLResponse: base64xml };

        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
          cert: 'MIICrjCCAZYCCQDWybyUsLVkXzANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDFA5hY21lX3Rvb2xzLmNvbTAeFw0xNTA4MTgwODQ3MzZaFw0yNTA4MTcwODQ3MzZaMBkxFzAVBgNVBAMUDmFjbWVfdG9vbHMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlyT+OzEymhaZFNfx4+HFxZbBP3egvcUgPvGa7wWCV7vyuCauLBqwO1FQqzaRDxkEihkHqmUz63D25v2QixLxXyqaFQ8TxDFKwYATtSL7x5G2Gww56H0L1XGgYdNW1akPx90P+USmVn1Wb//7AwU+TV+u4jIgKZyTaIFWdFlwBhlp4OBEHCyYwngFgMyVoCBsSmwb4if7Mi5T746J9ZMQpC+ts+kfzley59Nz55pa5fRLwu4qxFUv2oRdXAf2ZLuxB7DPQbRH82/ewZZ8N4BUGiQyAwOsHgp0sb9JJ8uEM/qhyS1dXXxjo+kxsI5HXhxp4P5R9VADuOquaLIo8ptIrQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBW/Y7leJnV76+6bzeqqi+buTLyWc1mASi5LVH68mdailg2WmGfKlSMLGzFkNtg8fJnfaRZ/GtxmSxhpQRHn63ZlyzqVrFcJa0qzPG21PXPHG/ny8pN+BV8fk74CIb/+YN7NvDUrV7jlsPxNT2rQk8G2fM7jsTMYvtz0MBkrZZsUzTv4rZkF/v44J/ACDirKJiE+TYArm70yQPweX6RvYHNZLSzgg4o+hoyBXo5BGQetAjmcIhC6ZOwN3iVhGjp0YpWM0pkqStPy3sIR0//LZbskWWlSRb0fX1c4632Xb+zikfec4DniYV6CxkB2U+plHpOX1rt1R+UiTEIhTSXPNt/',
          validateInResponseTo: true
        };
        var samlObj = new SAML( samlConfig );

        fakeClock = sinon.useFakeTimers(Date.parse('2014-06-05T12:07:07.662Z'));

        // Mock the SAML request being passed through Passport-SAML
        await samlObj.cacheProvider.save(requestId, new Date().toISOString());

        await samlObj.validatePostResponse( container ).should.be.rejectedWith({message: 'InResponseTo is missing from response'});
      });

      it( 'xml document with SubjectConfirmation and missing InResponseTo from request should be not problematic if not validated', async function(){
        var requestId = '_dfab47d5d46374cd4b71';
        var xml = '<samlp:Response ID="_f6c28a7d-9c82-4ae8-ba14-fc42c85081d3" Version="2.0" IssueInstant="2014-06-05T12:07:07.662Z" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">Verizon IDP Hub</saml:Issuer><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" /><Reference URI="#_f6c28a7d-9c82-4ae8-ba14-fc42c85081d3"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><InclusiveNamespaces PrefixList="#default samlp saml ds xs xsi" xmlns="http://www.w3.org/2001/10/xml-exc-c14n#" /></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" /><DigestValue>c8xR7YMU8KAYbkV7Jx3WEBhIqso=</DigestValue></Reference></SignedInfo><SignatureValue>jPOrsXdG/YVyGrykXYUbgVK7iX+tNFjMJnOA2iFWOjjtWco9M5DT9tyUsYAag4o4oDUEJribGWhCYn6nvQ24zfW+eJYGwbxO0TSZ26J0iuhnxr+MMFmJVGjxArD70dea0kITssqCxJNKUwmTqteAQ73+qk91H9E9IDoOjMwQERoyD4sAtvfJErRrRontvg9xeQ0BFtyMzJZkwU24QqHvoHyw9/dVO8/NFPydwjaI9uZMu6/QUYKKvkbf6VUXXQUHIiZgX0GCudpB908BqWIcj0dWv8oKGGajQWp+d8Jlx/nxbUTAs8vL1f0dxW3LYCZsDExHmjRQTBhM0pQVMT+HlA==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIICrjCCAZYCCQDWybyUsLVkXzANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDFA5hY21lX3Rvb2xzLmNvbTAeFw0xNTA4MTgwODQ3MzZaFw0yNTA4MTcwODQ3MzZaMBkxFzAVBgNVBAMUDmFjbWVfdG9vbHMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlyT+OzEymhaZFNfx4+HFxZbBP3egvcUgPvGa7wWCV7vyuCauLBqwO1FQqzaRDxkEihkHqmUz63D25v2QixLxXyqaFQ8TxDFKwYATtSL7x5G2Gww56H0L1XGgYdNW1akPx90P+USmVn1Wb//7AwU+TV+u4jIgKZyTaIFWdFlwBhlp4OBEHCyYwngFgMyVoCBsSmwb4if7Mi5T746J9ZMQpC+ts+kfzley59Nz55pa5fRLwu4qxFUv2oRdXAf2ZLuxB7DPQbRH82/ewZZ8N4BUGiQyAwOsHgp0sb9JJ8uEM/qhyS1dXXxjo+kxsI5HXhxp4P5R9VADuOquaLIo8ptIrQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBW/Y7leJnV76+6bzeqqi+buTLyWc1mASi5LVH68mdailg2WmGfKlSMLGzFkNtg8fJnfaRZ/GtxmSxhpQRHn63ZlyzqVrFcJa0qzPG21PXPHG/ny8pN+BV8fk74CIb/+YN7NvDUrV7jlsPxNT2rQk8G2fM7jsTMYvtz0MBkrZZsUzTv4rZkF/v44J/ACDirKJiE+TYArm70yQPweX6RvYHNZLSzgg4o+hoyBXo5BGQetAjmcIhC6ZOwN3iVhGjp0YpWM0pkqStPy3sIR0//LZbskWWlSRb0fX1c4632Xb+zikfec4DniYV6CxkB2U+plHpOX1rt1R+UiTEIhTSXPNt/</X509Certificate></X509Data></KeyInfo></Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status><saml:Assertion Version="2.0" ID="_ea67f283-0afb-465a-ba78-5abe7b7f8584" IssueInstant="2014-06-05T12:07:07.663Z" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>Verizon IDP Hub</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">UIS/jochen-work</saml:NameID><saml:SubjectConfirmation><saml:SubjectConfirmationData NotBefore="2014-06-05T12:06:07.664Z" NotOnOrAfter="2014-06-05T12:10:07.664Z" /></saml:SubjectConfirmation></saml:Subject><saml:AttributeStatement><saml:Attribute Name="vz::identity" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">UIS/jochen-work</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::subjecttype" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">UIS user</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::account" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">e9aba0c4-ece8-4b44-9526-d24418aa95dc</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::org" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">testorg</saml:AttributeValue></saml:Attribute><saml:Attribute Name="vz::name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">Test User</saml:AttributeValue></saml:Attribute><saml:Attribute Name="net::ip" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">::1</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
        var base64xml = Buffer.from( xml ).toString('base64');
        var container = { SAMLResponse: base64xml };

        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
          cert: 'MIICrjCCAZYCCQDWybyUsLVkXzANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDFA5hY21lX3Rvb2xzLmNvbTAeFw0xNTA4MTgwODQ3MzZaFw0yNTA4MTcwODQ3MzZaMBkxFzAVBgNVBAMUDmFjbWVfdG9vbHMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlyT+OzEymhaZFNfx4+HFxZbBP3egvcUgPvGa7wWCV7vyuCauLBqwO1FQqzaRDxkEihkHqmUz63D25v2QixLxXyqaFQ8TxDFKwYATtSL7x5G2Gww56H0L1XGgYdNW1akPx90P+USmVn1Wb//7AwU+TV+u4jIgKZyTaIFWdFlwBhlp4OBEHCyYwngFgMyVoCBsSmwb4if7Mi5T746J9ZMQpC+ts+kfzley59Nz55pa5fRLwu4qxFUv2oRdXAf2ZLuxB7DPQbRH82/ewZZ8N4BUGiQyAwOsHgp0sb9JJ8uEM/qhyS1dXXxjo+kxsI5HXhxp4P5R9VADuOquaLIo8ptIrQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBW/Y7leJnV76+6bzeqqi+buTLyWc1mASi5LVH68mdailg2WmGfKlSMLGzFkNtg8fJnfaRZ/GtxmSxhpQRHn63ZlyzqVrFcJa0qzPG21PXPHG/ny8pN+BV8fk74CIb/+YN7NvDUrV7jlsPxNT2rQk8G2fM7jsTMYvtz0MBkrZZsUzTv4rZkF/v44J/ACDirKJiE+TYArm70yQPweX6RvYHNZLSzgg4o+hoyBXo5BGQetAjmcIhC6ZOwN3iVhGjp0YpWM0pkqStPy3sIR0//LZbskWWlSRb0fX1c4632Xb+zikfec4DniYV6CxkB2U+plHpOX1rt1R+UiTEIhTSXPNt/',
          validateInResponseTo: false
        };
        var samlObj = new SAML( samlConfig );

        fakeClock = sinon.useFakeTimers(Date.parse('2014-06-05T12:07:07.662Z'));

        // Mock the SAML request being passed through Passport-SAML
        await samlObj.cacheProvider.save(requestId, new Date().toISOString());

        const {profile} = await samlObj.validatePostResponse( container );

        profile.nameID.should.startWith( 'UIS/jochen-work' );
        const value = await samlObj.cacheProvider.get(requestId);
        should.exist(value);
        value.should.eql('2014-06-05T12:07:07.662Z');
      });

      it( 'xml document with multiple AttributeStatements should have all attributes present on profile', async function(){
        var requestId = '_dfab47d5d46374cd4b71';
        var xml = '<samlp:Response ID="_f6c28a7d-9c82-4ae8-ba14-fc42c85081d3" InResponseTo="_dfab47d5d46374cd4b71" Version="2.0" IssueInstant="2014-06-05T12:07:07.662Z" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">Verizon IDP Hub</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion Version="2.0" ID="_ea67f283-0afb-465a-ba78-5abe7b7f8584" IssueInstant="2014-06-05T12:07:07.663Z" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>Verizon IDP Hub</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">UIS/jochen-work</saml:NameID><saml:SubjectConfirmation><saml:SubjectConfirmationData NotBefore="2014-06-05T12:06:07.664Z" NotOnOrAfter="2014-06-05T12:10:07.664Z" InResponseTo="_dfab47d5d46374cd4b71"/></saml:SubjectConfirmation></saml:Subject><saml:AttributeStatement><saml:Attribute Name="vz::identity" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">UIS/jochen-work</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AttributeStatement><saml:Attribute Name="vz::subjecttype" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">UIS user</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AttributeStatement><saml:Attribute Name="vz::account" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">e9aba0c4-ece8-4b44-9526-d24418aa95dc</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AttributeStatement><saml:Attribute Name="vz::org" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">testorg</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AttributeStatement><saml:Attribute Name="vz::name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">Test User</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AttributeStatement><saml:Attribute Name="net::ip" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">::1</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI="#_f6c28a7d-9c82-4ae8-ba14-fc42c85081d3"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>qD+sVCaEdy1dTJoUQdo6o+tYsuU=</DigestValue></Reference></SignedInfo><SignatureValue>aLl+1yT7zdT4WnRXKh9cx7WWZnUi/NoxMJWhXP5d+Zu9A4/fjKApSywimU0MTTQxYpvZLjOZPsSwmvc1boJOlXveDsL7A3YWi/f7/zqlVWOfXLE8TVLqUE4jtLsJHFWIJXmh8CI0loqQNf6QcYi9BwCK82FhhXC+qWA5WCZIIWUUMxjxnPbunQ7mninEeW568wqyhb9pLV8QkThzZrZINCqxNvWyGuK/XGPx7ciD6ywbBkdOjlDbwRMaKQ9YeCzZGGzJwOe/NuCXj+oUyzfmzUCobIIR0HYLc4B5UplL7XIKQzpOA2lDDsLe6ZzdTv1qjxSm+dlVfo24onmiPlQUgA==</SignatureValue></Signature></samlp:Response>';
        var base64xml = Buffer.from( xml ).toString('base64');
        var container = { SAMLResponse: base64xml };

        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
          cert: 'MIIDtTCCAp2gAwIBAgIJAKg4VeVcIDz1MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTUwODEzMDE1NDIwWhcNMTUwOTEyMDE1NDIwWjBFMQswCQYDVQQGEwJVUzETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxG3ouM7U+fXbJt69X1H6d4UNg/uRr06pFuU9RkfIwNC+yaXyptqB3ynXKsL7BFt4DCd0fflRvJAx3feJIDp16wN9GDVHcufWMYPhh2j5HcTW/j9JoIJzGhJyvO00YKBt+hHy83iN1SdChKv5y0iSyiPP5GnqFw+ayyHoM6hSO0PqBou1Xb0ZSIE+DHosBnvVna5w2AiPY4xrJl9yZHZ4Q7DfMiYTgstjETio4bX+6oLiBnYktn7DjdEslqhffVme4PuBxNojI+uCeg/sn4QVLd/iogMJfDWNuLD8326Mi/FE9cCRvFlvAiMSaebMI3zPaySsxTK7Zgj5TpEbmbHI9wIDAQABo4GnMIGkMB0GA1UdDgQWBBSVGgvoW4MhMuzBGce29PY8vSzHFzB1BgNVHSMEbjBsgBSVGgvoW4MhMuzBGce29PY8vSzHF6FJpEcwRTELMAkGA1UEBhMCVVMxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJAKg4VeVcIDz1MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAJu1rqs+anD74dbdwgd3CnqnQsQDJiEXmBhG2leaGt3ve9b/9gKaJg2pyb2NyppDe1uLqh6nNXDuzg1oNZrPz5pJL/eCXPl7FhxhMUi04TtLf8LeNTCIWYZiFuO4pmhohHcv8kRvYR1+6SkLTC8j/TZerm7qvesSiTQFNapa1eNdVQ8nFwVkEtWl+JzKEM1BlRcn42sjJkijeFp7DpI7pU+PnYeiaXpRv5pJo8ogM1iFxN+SnfEs0EuQ7fhKIG9aHKi7bKZ7L6SyX7MDIGLeulEU6lf5D9BfXNmcMambiS0pXhL2QXajt96UBq8FT2KNXY8XNtR4y6MyyCzhaiZZcc8=',
          validateInResponseTo: true
        };
        var samlObj = new SAML( samlConfig );

        fakeClock = sinon.useFakeTimers(Date.parse('2014-06-05T12:07:07.662Z'));

        // Mock the SAML request being passed through Passport-SAML
        await samlObj.cacheProvider.save(requestId, new Date().toISOString());

        const {profile} = await samlObj.validatePostResponse( container );

        profile.nameID.should.startWith( 'UIS/jochen-work' );
        profile['vz::identity'].should.equal( 'UIS/jochen-work' );
        profile['vz::subjecttype'].should.equal( 'UIS user' );
        profile['vz::account'].should.equal( 'e9aba0c4-ece8-4b44-9526-d24418aa95dc' );
        profile['vz::org'].should.equal( 'testorg' );
        profile['vz::name'].should.equal( 'Test User' );
        profile['net::ip'].should.equal( '::1' );
        const value = await samlObj.cacheProvider.get(requestId);
        should.not.exist(value);
      });

      describe( 'InResponseTo server cache expiration tests /', function() {
        it( 'should expire a cached request id after the time', async function(){
          var requestId = '_dfab47d5d46374cd4b71';

          var samlConfig = {
            validateInResponseTo: true,
            requestIdExpirationPeriodMs: 100
          };
          var samlObj = new SAML( samlConfig );

          // Mock the SAML request being passed through Passport-SAML
          await samlObj.cacheProvider.save(requestId, new Date().toISOString());
          await new Promise(resolve => setTimeout(resolve, 300));

          const value = await samlObj.cacheProvider.get(requestId);
          should.not.exist(value);
        });

        it( 'should expire many cached request ids after the time', async function(){
          var expiredRequestId1 = '_dfab47d5d46374cd4b71';
          var expiredRequestId2 = '_dfab47d5d46374cd4b72';
          var requestId = '_dfab47d5d46374cd4b73';

          var samlConfig = {
            validateInResponseTo: true,
            requestIdExpirationPeriodMs: 100
          };
          var samlObj = new SAML( samlConfig );

          await samlObj.cacheProvider.save(expiredRequestId1, new Date().toISOString());
          await samlObj.cacheProvider.save(expiredRequestId2, new Date().toISOString());

          await new Promise(resolve => setTimeout(resolve, 300));
          // Add one more that shouldn't expire
          await samlObj.cacheProvider.save(requestId, new Date().toISOString());

          const value1 = await samlObj.cacheProvider.get(expiredRequestId1);
          should.not.exist(value1);

          const value2 = await samlObj.cacheProvider.get(expiredRequestId2);
          should.not.exist(value2);

          const value3 = await samlObj.cacheProvider.get(requestId);
          should.exist(value3);

          // Let the expiration timer run again and we should have no more cached
          await new Promise(resolve => setTimeout(resolve, 300));

          const value4 = await samlObj.cacheProvider.get(requestId);

          should.not.exist(value4);
        });
      });
    });

    describe( 'assertion condition checks /', function() {
      var samlConfig = {
        entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
        cert: TEST_CERT,
      };
      var fakeClock;

      beforeEach(function() {
        fakeClock = sinon.useFakeTimers(Date.parse('2014-05-28T00:13:09Z'));
      });

      afterEach(function() {
        fakeClock.restore();
      });

      it( 'onelogin xml document with current time after NotBefore time should validate', async function() {
        var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
        '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+TEST_CERT+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
        '</samlp:Response>';
        var base64xml = Buffer.from( xml ).toString('base64');
        var container = { SAMLResponse: base64xml };
        var samlObj = new SAML( samlConfig );

        // Fake the current date to be within the valid time range
        fakeClock.restore();
        fakeClock = sinon.useFakeTimers(Date.parse('2014-05-28T00:13:09Z'));

        const {profile} = await samlObj.validatePostResponse( container );

        profile.nameID.should.startWith( 'ploer' );
      });

      it( 'onelogin xml document with current time equal to NotBefore (plus default clock skew)  time should validate', async function( ) {
        var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
        '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+TEST_CERT+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
        '</samlp:Response>';
        var base64xml = Buffer.from( xml ).toString('base64');
        var container = { SAMLResponse: base64xml };
        var samlObj = new SAML( samlConfig );

        // Fake the current date to be within the valid time range
        fakeClock.restore();
        fakeClock = sinon.useFakeTimers(Date.parse('2014-05-28T00:13:08Z'));

        const {profile} = await samlObj.validatePostResponse( container );

        profile.nameID.should.startWith( 'ploer' );
      });

      it( 'onelogin xml document with current time before NotBefore time should fail', async function( ) {
        var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
        '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+TEST_CERT+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
        '</samlp:Response>';
        var base64xml = Buffer.from( xml ).toString('base64');
        var container = { SAMLResponse: base64xml };
        var samlObj = new SAML( samlConfig );

        // Fake the current date to be after the valid time range
        fakeClock.restore();
        fakeClock = sinon.useFakeTimers(Date.parse('2014-05-28T00:13:07Z'));

        await samlObj.validatePostResponse( container ).should.be.rejectedWith({message: 'SAML assertion not yet valid'});
      });

      it( 'onelogin xml document with current time equal to NotOnOrAfter (minus default clock skew) time should fail', async function( ) {
        var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
        '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+TEST_CERT+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
        '</samlp:Response>';
        var base64xml = Buffer.from( xml ).toString('base64');
        var container = { SAMLResponse: base64xml };
        var samlObj = new SAML( samlConfig );

        // Fake the current date to be after the valid time range
        fakeClock.restore();
        fakeClock = sinon.useFakeTimers(Date.parse('2014-05-28T00:19:08Z'));

        await samlObj.validatePostResponse( container ).should.be.rejectedWith({message: 'SAML assertion expired'});
      });

      it( 'onelogin xml document with current time after NotOnOrAfter time (minus default clock skew) should fail', async function() {
        var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
        '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+TEST_CERT+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
        '</samlp:Response>';
        var base64xml = Buffer.from( xml ).toString('base64');
        var container = { SAMLResponse: base64xml };
        var samlObj = new SAML( samlConfig );

        // Fake the current date to be after the valid time range
        fakeClock.restore();
        fakeClock = sinon.useFakeTimers(Date.parse('2014-05-28T00:19:09Z'));

        await samlObj.validatePostResponse( container ).should.be.rejectedWith({message: 'SAML assertion expired'});

      });

      it( 'onelogin xml document with current time after NotOnOrAfter time with accepted clock skew equal to -1 should pass', async function( ) {
        var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
        '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+TEST_CERT+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
        '</samlp:Response>';
        var base64xml = Buffer.from( xml ).toString('base64');
        var container = { SAMLResponse: base64xml };

        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
          cert: TEST_CERT,
          acceptedClockSkewMs: -1
        };
        var samlObj = new SAML( samlConfig );

        // Fake the current date to be after the valid time range
        fakeClock.restore();
        fakeClock = sinon.useFakeTimers(Date.parse('2014-05-28T00:20:09Z'));

        const {profile} = await samlObj.validatePostResponse( container );

        profile.nameID.should.startWith( 'ploer' );
      });

      it( 'onelogin xml document with audience and no AudienceRestriction should not pass', async function( ) {
        var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
        '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+TEST_CERT+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
        '</samlp:Response>';
        var base64xml = Buffer.from( xml ).toString('base64');
        var container = { SAMLResponse: base64xml };

        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
          audience: 'http://sp.example.com',
          acceptedClockSkewMs: -1
        };
        var samlObj = new SAML( samlConfig );

        await samlObj.validatePostResponse( container ).should.be.rejectedWith({message: 'SAML assertion has no AudienceRestriction'});
      });

      it( 'onelogin xml document with audience not matching AudienceRestriction should not pass', async function( ) {
        var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
        '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+TEST_CERT+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
        '</samlp:Response>';
        var base64xml = Buffer.from( xml ).toString('base64');
        var container = { SAMLResponse: base64xml };

        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
          audience: 'http://sp.example.com',
          acceptedClockSkewMs: -1
        };
        var samlObj = new SAML( samlConfig );

        await samlObj.validatePostResponse( container ).should.be.rejectedWith({message: 'SAML assertion audience mismatch'});
      });

      it( 'onelogin xml document with audience matching AudienceRestriction should pass', async function( ) {
        var xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R689b0733bccca22a137e3654830312332940b1be" Version="2.0" IssueInstant="2014-05-28T00:16:08Z" Destination="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
        '<saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa" IssueInstant="2014-05-28T00:16:08Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/371755</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx3b63c7be-fe86-62fd-8cb5-16ab6273efaa"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>DCnPTQYBb1hKspbe6fg1U3q8xn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>e0+aFomA0+JAY0f9tKqzIuqIVSSw7LiFUsneEDKPBWdiTz1sMdgr/2y1e9+rjaS2mRmCi/vSQLY3zTYz0hp6nJNU19+TWoXo9kHQyWT4KkeQL4Xs/gZ/AoKC20iHVKtpPps0IQ0Ml/qRoouSitt6Sf/WDz2LV/pWcH2hx5tv3xSw36hK2NQc7qw7r1mEXnvcjXReYo8rrVf7XHGGxNoRIEICUIi110uvsWemSXf0Z0dyb0FVYOWuSsQMDlzNpheADBifFO4UTfSEhFZvn8kVCGZUIwrbOhZ2d/+YEtgyuTg+qtslgfy4dwd4TvEcfuRzQTazeefprSFyiQckAXOjcw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'+TEST_CERT+'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ploer@subspacesw.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-05-28T00:19:08Z" Recipient="{recipient}" InResponseTo="_a6fc46be84e1e3cf3c50"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-05-28T00:13:08Z" NotOnOrAfter="2014-05-28T00:19:08Z"><saml:AudienceRestriction><saml:Audience>http://sp.example.com</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-05-28T00:16:07Z" SessionNotOnOrAfter="2014-05-29T00:16:08Z" SessionIndex="_30a4af50-c82b-0131-f8b5-782bcb56fcaa"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>' +
        '</samlp:Response>';
        var base64xml = Buffer.from( xml ).toString('base64');
        var container = { SAMLResponse: base64xml };

        var samlConfig = {
          entryPoint: 'https://app.onelogin.com/trust/saml2/http-post/sso/371755',
          audience: 'http://sp.example.com',
          acceptedClockSkewMs: -1
        };
        var samlObj = new SAML( samlConfig );

        const {profile} = await samlObj.validatePostResponse( container );

        profile.nameID.should.startWith( 'ploer' );
      });

    });
  });
  describe('validatePostRequest()', function() {
    var samlObj;
    beforeEach(function() {
      samlObj = new SAML({
        cert: fs.readFileSync(__dirname + '/static/cert.pem', 'ascii')
      });
    });

    it('errors if bad xml', async function() {
      var body = {
        SAMLRequest: 'asdf'
      };
      await samlObj.validatePostRequest(body).should.be.rejected();
    });
    it('errors if bad signature', async function() {
      var body = {
        SAMLRequest: fs.readFileSync(__dirname + '/static/logout_request_with_bad_signature.xml', 'base64')
      };
      await samlObj.validatePostRequest(body).should.be.rejectedWith(new Error('Invalid signature on documentElement'));
    });
    it('returns profile for valid signature', async function() {
      var body = {
        SAMLRequest: fs.readFileSync(__dirname + '/static/logout_request_with_good_signature.xml', 'base64')
      };
      const {profile} = await samlObj.validatePostRequest(body);

      profile.should.eql({
        ID: 'pfxd4d369e8-9ea1-780c-aff8-a1d11a9862a1',
        issuer: 'http://sp.example.com/demo1/metadata.php',
        nameID: 'ONELOGIN_f92cc1834efc0f73e9c09f482fce80037a6251e7',
        nameIDFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
      });
    });
    it('returns profile for valid signature including session index', async function() {
      var body = {
        SAMLRequest: fs.readFileSync(__dirname + '/static/logout_request_with_session_index.xml', 'base64')
      };
      const {profile} = await samlObj.validatePostRequest(body);

      profile.should.eql({
        ID: 'pfxd4d369e8-9ea1-780c-aff8-a1d11a9862a1',
        issuer: 'http://sp.example.com/demo1/metadata.php',
        nameID: 'ONELOGIN_f92cc1834efc0f73e9c09f482fce80037a6251e7',
        nameIDFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        sessionIndex: '1'
      });
    });
    it('returns profile for valid signature with encrypted nameID', async function() {
      var samlObj = new SAML({
        cert: fs.readFileSync(__dirname + '/static/cert.pem', 'ascii'),
        decryptionPvk: fs.readFileSync(__dirname + '/static/key.pem', 'ascii')
      });
      var body = {
        SAMLRequest: fs.readFileSync(__dirname + '/static/logout_request_with_encrypted_name_id.xml', 'base64')
      };
      const {profile} = await samlObj.validatePostRequest(body);

      profile.should.eql({
        ID: 'pfx00cb5227-d9d0-1d4b-bdb2-c7ad6c3c6906',
        issuer: 'http://sp.example.com/demo1/metadata.php',
        nameID: 'ONELOGIN_f92cc1834efc0f73e9c09f482fce80037a6251e7',
        nameIDFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        sessionIndex: '1'
      });
    });
    it('errors if bad privateCert to _requestToURL', async function() {
      var samlObj = new SAML({
        entryPoint: 'http://localhost',
        privateCert: '-----BEGIN CERTIFICATE-----\n'+
          '8mvhvrcCOiJ3mjgKNN1F31jOBJuZNmq0U7n9v+Z+3NfyU/0E9jkrnFvm5ks+p8kl\n' +
          'BjuBk9RAkazsU9l02XMS/VxOOIifxKC7R9bDtx0hjolYxgqxPIO5s4rmjj0rLzvo\n' +
          'vQTTTx/tB5e+hbdx922QSeTjP4DO4ms6cIexcH+ZEUOJ3wXiHToJW83SXLRtwPI9\n' +
          'JbWKeS9nWPnzcedbDNZkGtohW5vf32BHuvLsWcl6eFXRSkdX/7+rgpXmDRB7caQ+\n' +
          '2SXVY7ORily7LTKg1cFmuKHDzKTGFIp5/GU6dwIDAQABAoIBAArgFQ+Uk4UN4diY\n' +
          'gJWCAaQlTVmP0UEHZQt/NmJrc9ZVduuhOP0hH6gF53nREHz5UQb4nXB2Ksa3MtYD\n' +
          'Z1vhJcu/T7pvmib4q+Ij6oAmlyeL/xwVY3IUURMxX3tCdPItlk4PEFELKeqQOiIS\n' +
          '7B0DYxWfJbMle3c95w5ruYEr2A+fHCKVSlDpg7uPd9VQ6t7bGMZZvc9tDSC1qPXQ\n' +
          'Gd/WOMXxi+t/TpyVZ6tOcEekQzAMLmWElUUPx3TJ0ur0Zl2LZ7IvQEXXias4lUHV\n' +
          'fnH3akDCMmdhlJSVqUfplrh85zAOh6fLloZagphj/Kpgfw1TZ+njSDYqSLYE0NZ1\n' +
          'j+83feECgYEA2aNGgbc+t6QLrJJ63l9Mz541lVV3IUAxZ5ACqOnMkQVuLoa5IMwM\n' +
          'oENIo38ptfHQqjQ9x8/tEINFqOHnQuOJ/+1xP9f0Me+0clRDCqjGYqNYgmakKyD7\n' +
          'vey/q6kwHk679RVGiI1p+HdoA+CbEKWHJiRxE0RhAA3G3wGAq7kpJocCgYEAxp4/\n' +
          'tCft+eHVRivspfDN//axc2TR6qWP9E1ueGvbiXPXv0Puag0W9cER/df/s5jW4Rqg\n' +
          'CE8649HPUZ0FJT+YaeKgu2Sw9SMcGl4/uyHzg7KnXIeYyQZJPqQkKyXmIix8cw3+\n' +
          'HBGRtwX5nOy0DgFdaMiH0F08peNI9QHKKTBoWJECgYEAyymJ1ekzWMaAR1Zt8EvS\n' +
          'LjWoG4EuthFwjRZ4BSpLVk1Vb4VAKAeS+cAVfNpmG3xip6Ag0/ebe0CvtFk9QsmZ\n' +
          'txj2EP0M7div/9H8y2SF3OpS41fhhIlDtyXcPuivDHu/Jaf4sdwgwlrk9EmlN0Lu\n' +
          'CIMYMz4vtpclwGNss+EjMt0CgYEAqepD0Vm/iuCaVhfJsgSaFvnywSdlNfpBdtyv\n' +
          'PzH2dFa4IZZ55hwgoklznNgmlnyQh68BbVpqpO+fDtDnz//h4ePRYb84a96Hcj9j\n' +
          'AjJ/YxF5f/04xfEsw/wkPQ2FHYM1TDCSTWzyXcMs0gTl3H1qbfPvzF+XPMt+ZKwN\n' +
          'SMNy4SECgYB3ig6t+XVfNkw8oBOh0Gx37XKbmImXsA8ucDAX9KUbMIvD03XCEf34\n' +
          'jF3SNJh0SmHoT62vc+cJqPxMDP6E7Q1nZxsEyaAkKr2H4dSM4SlRm0VB+bS+jXsz\n' +
          'PCiRGSm8eupuxfix05LMMreo4mC7e3Ir4JhdCsXxAMZIvbNyXcvUMA==\n' +
          '-----END CERTIFICATE-----\n'
      });
      var request = '<?xml version=\\"1.0\\"?><samlp:AuthnRequest xmlns:samlp=\\"urn:oasis:names:tc:SAML:2.0:protocol\\" ID=\\"_ea40a8ab177df048d645\\" Version=\\"2.0\\" IssueInstant=\\"2017-08-22T19:30:01.363Z\\" ProtocolBinding=\\"urn:oasis:names$tc:SAML:2.0:bindings:HTTP-POST\\" AssertionConsumerServiceURL=\\"https://example.com/login/callback\\" Destination=\\"https://www.example.com\\"><saml:Issuer xmlns:saml=\\"urn:oasis:names:tc:SAML:2.0:assertion\\">onelogin_saml</saml:Issuer><s$mlp:NameIDPolicy xmlns:samlp=\\"urn:oasis:names:tc:SAML:2.0:protocol\\" Format=\\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\\" AllowCreate=\\"true\\"/><samlp:RequestedAuthnContext xmlns:samlp=\\"urn:oasis:names:tc:SAML:2.0:protoc$l\\" Comparison=\\"exact\\"><saml:AuthnContextClassRef xmlns:saml=\\"urn:oasis:names:tc:SAML:2.0:assertion\\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp$AuthnRequest>';

      await samlObj._requestToUrl(request, null, 'authorize', {}).should.be.rejectedWith(/no start line/);
    });
  });

  describe('validateRedirect()', function() {
    describe('idp slo', function() {
      var samlObj;
      beforeEach(function() {
        samlObj = new SAML({
          cert: fs.readFileSync(__dirname + '/static/acme_tools_com.cert', 'ascii'),
          idpIssuer: 'http://localhost:20000/saml2/idp/metadata.php'
        });
        this.request = Object.assign({}, require('./static/idp_slo_redirect'));
        this.clock = sinon.useFakeTimers(Date.parse('2018-04-11T14:08:00Z'));
      });
      afterEach(function() {
        this.clock.restore();
      });
      it('errors if bad xml', async function() {
        var body = {
          SAMLRequest: 'asdf'
        };
        await samlObj.validateRedirect(body, this.request.originalQuery).should.be.rejected();
      });
      it('errors if idpIssuer is set and issuer is wrong', async function() {
        samlObj.options.idpIssuer = 'foo';
        await samlObj.validateRedirect(this.request, this.request.originalQuery).should.be.rejectedWith({message: 'Unknown SAML issuer. Expected: foo Received: http://localhost:20000/saml2/idp/metadata.php'});
      });
      it('errors if request has expired', async function() {
        this.clock.restore();
        await samlObj.validateRedirect(this.request, this.request.originalQuery).should.be.rejectedWith({message: 'SAML assertion expired'});
      });
      it('errors if request has a bad signature', async function() {
        this.request.Signature = 'foo';
        await samlObj.validateRedirect(this.request, this.request.originalQuery).should.be.rejectedWith({message: 'Invalid signature'});
      });
      it('returns profile for valid signature including session index', async function() {
        const {profile} = await samlObj.validateRedirect(this.request, this.request.originalQuery);

        profile.should.eql({
          ID: '_8f0effde308adfb6ae7f1e29b414957fc320f5636f',
          issuer: 'http://localhost:20000/saml2/idp/metadata.php',
          nameID: 'stavros@workable.com',
          nameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
          sessionIndex: '_00bf7b2d5d9d3c970217eecefb1194bef3362a618e'
        });
      });
    });
    describe('sp slo', function() {
      var samlObj;
      beforeEach(function() {
        samlObj = new SAML({
          cert: fs.readFileSync(__dirname + '/static/acme_tools_com.cert', 'ascii'),
          idpIssuer: 'http://localhost:20000/saml2/idp/metadata.php',
          validateInResponseTo: true
        });
        this.request = Object.assign({}, require('./static/sp_slo_redirect'));
        this.clock = sinon.useFakeTimers(Date.parse('2018-04-11T14:08:00Z'));
      });
      afterEach(async function() {
        this.clock.restore();
        await samlObj.cacheProvider.remove('_79db1e7ad12ca1d63e5b');
      });
      it('errors if bad xml', async function() {
        var body = {
          SAMLRequest: 'asdf'
        };
        await samlObj.validateRedirect(body).should.be.rejected();
      });
      it('errors if idpIssuer is set and wrong issuer', async function() {
        samlObj.options.idpIssuer = 'foo';
        await samlObj.validateRedirect(this.request, this.request.originalQuery).should.be.rejectedWith({message: 'Unknown SAML issuer. Expected: foo Received: http://localhost:20000/saml2/idp/metadata.php'});
      });
      it('errors if unsuccessful', async function() {
        this.request = require('./static/sp_slo_redirect_failure');
        await samlObj.validateRedirect(this.request, this.request.originalQuery).should.be.rejectedWith({message: 'Bad status code: urn:oasis:names:tc:SAML:2.0:status:Requester'});
      });
      it('errors if InResponseTo is not found', async function() {
        await samlObj.validateRedirect(this.request, this.request.originalQuery).should.be.rejectedWith({message: 'InResponseTo is not valid'});
      });
      it('errors if bad signature', async function() {
        await samlObj.cacheProvider.save('_79db1e7ad12ca1d63e5b', new Date().toISOString());
        this.request.Signature = 'foo';
        await samlObj.validateRedirect(this.request, this.request.originalQuery).should.be.rejectedWith({message: 'Invalid signature'});
      });

      it('returns true for valid signature', async function() {
        await samlObj.cacheProvider.save('_79db1e7ad12ca1d63e5b', new Date().toISOString());

        const {success} = await samlObj.validateRedirect(this.request, this.request.originalQuery);
        success.should.eql(true);
      });

      it('accepts cert without header and footer line', async function() {
        samlObj.options.cert = fs.readFileSync(__dirname + '/static/acme_tools_com_without_header_and_footer.cert', 'ascii');
        await samlObj.cacheProvider.save('_79db1e7ad12ca1d63e5b', new Date().toISOString());
        const {success} = await samlObj.validateRedirect(this.request, this.request.originalQuery);

        success.should.eql(true);
      });
    });
  });
});
