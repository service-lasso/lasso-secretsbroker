package main

import (
	"context"
	"net"
	"strings"
)

type transportPeerIdentity struct {
	Kind    string
	Subject string
}

type transportPeerIdentityProvider interface {
	TransportPeerIdentity() transportPeerIdentity
}

type transportIdentityConn struct {
	net.Conn
	identity transportPeerIdentity
}

type transportPeerIdentityContextKey struct{}

func withTransportPeerIdentityConn(conn net.Conn, identity transportPeerIdentity) net.Conn {
	identity = normalizeTransportPeerIdentity(identity)
	if identity.Kind == "" || identity.Subject == "" {
		return conn
	}
	return &transportIdentityConn{Conn: conn, identity: identity}
}

func (c *transportIdentityConn) TransportPeerIdentity() transportPeerIdentity {
	return c.identity
}

func transportPeerIdentityConnContext(ctx context.Context, conn net.Conn) context.Context {
	provider, ok := conn.(transportPeerIdentityProvider)
	if !ok {
		return ctx
	}
	return contextWithTransportPeerIdentity(ctx, provider.TransportPeerIdentity())
}

func contextWithTransportPeerIdentity(ctx context.Context, identity transportPeerIdentity) context.Context {
	identity = normalizeTransportPeerIdentity(identity)
	if identity.Kind == "" || identity.Subject == "" {
		return ctx
	}
	return context.WithValue(ctx, transportPeerIdentityContextKey{}, identity)
}

func transportPeerIdentityFromContext(ctx context.Context) transportPeerIdentity {
	identity, _ := ctx.Value(transportPeerIdentityContextKey{}).(transportPeerIdentity)
	return normalizeTransportPeerIdentity(identity)
}

func normalizeTransportPeerIdentity(identity transportPeerIdentity) transportPeerIdentity {
	return transportPeerIdentity{
		Kind:    strings.ToLower(strings.TrimSpace(identity.Kind)),
		Subject: strings.TrimSpace(identity.Subject),
	}
}
