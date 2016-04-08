package ocsptls

import (
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

type OSCPResponse struct {
	RawResponse []byte
	response *ocsp.Response
	certificate *x509.Certificate
	issuer *x509.Certificate
}

func newOCSPResponse(certificate, issuer *x509.Certificate, rawResponse []byte) (*OSCPResponse, error) {
	parsedResponse, err := ocsp.ParseResponse(rawResponse, issuer)
	if err != nil {
		return nil, err
	}
	return &OSCPResponse{RawResponse: rawResponse, response: parsedResponse, certificate: certificate, issuer: issuer}, nil
}

func FetchOSCPResponse(certificate, issuer *x509.Certificate) (*OSCPResponse, error) {
	response, err := fetch(certificate, issuer)
	if err != nil {
		return nil, err
	}
  return newOCSPResponse(certificate, issuer, response)
}

func (ocspResponse *OSCPResponse) ValidUntil() time.Time {
	return ocspResponse.response.NextUpdate
}

func fetch(certificate, issuer *x509.Certificate) ([]byte, error) {
	ocspUrl, err := generateUrl(certificate, issuer)
	if err != nil {
		return nil, err
	}
	response, err := http.Get(ocspUrl)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	return ioutil.ReadAll(response.Body)
}

func generateOCSPRequest(cert, issuer *x509.Certificate) (string, error) {
	request, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(request), nil
}

func extractOCSPUrl(certificate *x509.Certificate) (string, error) {
	return certificate.OCSPServer[0], nil
}

func generateUrl(cert, issuer *x509.Certificate) (string, error) {
	baseUrl, err := extractOCSPUrl(cert)
	if err != nil {
		return "", err
	}
	path, err := generateOCSPRequest(cert, issuer)
	if err != nil {
		return "", err
	}
	return baseUrl + path, nil
}
