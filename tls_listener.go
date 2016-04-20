package ocsptls

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type OcspTLSListener interface {
	UpdateTLSConfig(cfg *tls.Config)
}

type ocspTlsListener struct {
	net.Listener
	tlsConfigWriteMutex sync.Mutex
	tlsConfig atomic.Value
	donePolling chan interface{}
	pollersWaitGroup sync.WaitGroup
}

func NewOcspTLSListener(inner net.Listener, config *tls.Config) net.Listener {
	listener := &ocspTlsListener{Listener: inner}
	listener.tlsConfig.Store(cloneTLSConfig(config))
	listener.startPollers()
	return listener
}

func (ln *ocspTlsListener) Accept() (c net.Conn, err error) {
	tc, err := ln.Listener.Accept()
	if err != nil {
		return
	}

	return tls.Server(tc, ln.tlsConfig.Load().(*tls.Config)), nil
}

func (ln *ocspTlsListener) Close() error {
	close(ln.donePolling)
	return ln.Listener.Close()
}

func (ln *ocspTlsListener) UpdateTLSConfig(cfg *tls.Config) {
	ln.stopPollers()
	ln.updateTLSConfig(cfg)
	ln.startPollers()
}

func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return &tls.Config{
		Rand:                     cfg.Rand,
		Time:                     cfg.Time,
		Certificates:             cfg.Certificates,
		NameToCertificate:        cfg.NameToCertificate,
		GetCertificate:           cfg.GetCertificate,
		RootCAs:                  cfg.RootCAs,
		NextProtos:               cfg.NextProtos,
		ServerName:               cfg.ServerName,
		ClientAuth:               cfg.ClientAuth,
		ClientCAs:                cfg.ClientCAs,
		InsecureSkipVerify:       cfg.InsecureSkipVerify,
		CipherSuites:             cfg.CipherSuites,
		PreferServerCipherSuites: cfg.PreferServerCipherSuites,
		SessionTicketsDisabled:   cfg.SessionTicketsDisabled,
		SessionTicketKey:         cfg.SessionTicketKey,
		ClientSessionCache:       cfg.ClientSessionCache,
		MinVersion:               cfg.MinVersion,
		MaxVersion:               cfg.MaxVersion,
		CurvePreferences:         cfg.CurvePreferences,
	}
}

func (ln *ocspTlsListener) startPollers() {
	ln.donePolling = make(chan interface{})
	for i, cert := range ln.tlsConfig.Load().(*tls.Config).Certificates {
		go func(index int, crt tls.Certificate) {
			certificates, _ := x509.ParseCertificates(append(crt.Certificate[0], crt.Certificate[1]...))
			ln.startPoller(index, certificates)
		}(i, cert)
	}
}

func (ln *ocspTlsListener) stopPollers() {
	close(ln.donePolling)
	ln.pollersWaitGroup.Wait()
}

func (ln *ocspTlsListener) restartPollers() {
	ln.stopPollers()
	ln.startPollers()
}

func (ln *ocspTlsListener) startPoller(index int, certificates []*x509.Certificate) {
	ln.pollersWaitGroup.Add(1)
	defer ln.pollersWaitGroup.Done()
	for {
		response, err := fetchOCSPResponse(certificates[0], certificates[1])
		if err != nil {
			log.Print(err)
			<-time.After(time.Minute)
			continue
		}
		ln.setOCSPResponse(index, response.RawResponse)
		timeToNextUpdate := time.Duration(float32(response.ValidUntil().Sub(time.Now())) * 0.9)
		select {
			case <-time.After(timeToNextUpdate):
				continue
			case <-ln.donePolling:
				return
			}
	}
}

func (ln *ocspTlsListener) setOCSPResponse(certIndex int, response []byte) {
	config := cloneTLSConfig(ln.tlsConfig.Load().(*tls.Config))
	config.Certificates[certIndex].OCSPStaple = response
	ln.updateTLSConfig(config)
}

func (ln *ocspTlsListener) updateTLSConfig(cfg *tls.Config) {
	ln.tlsConfigWriteMutex.Lock()
	defer ln.tlsConfigWriteMutex.Unlock()
	ln.tlsConfig.Store(cfg)
}

func fetchOCSPResponse(cert, issuer *x509.Certificate) (*OSCPResponse, error) {
	return FetchOSCPResponse(cert, issuer)
}
