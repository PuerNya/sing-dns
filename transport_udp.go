package dns

import (
	"context"
	"net"
	"net/url"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/miekg/dns"
)

var _ Upstream = (*UDPUpstream)(nil)

func init() {
	RegisterUpstream([]string{"udp", ""}, func(options UpstreamOptions) (Upstream, error) {
		return NewUDPUpstream(options)
	})
}

type UDPUpstream struct {
	myUpstreamAdapter
	tcpUpstream *TCPUpstream
	logger      logger.ContextLogger
	udpSize     int
}

func NewUDPUpstream(options UpstreamOptions) (*UDPUpstream, error) {
	var serverAddr M.Socksaddr
	if serverURL, err := url.Parse(options.Address); err != nil || serverURL.Scheme == "" {
		serverAddr = M.ParseSocksaddr(options.Address)
	} else {
		serverAddr = M.ParseSocksaddr(serverURL.Host)
	}
	if !serverAddr.IsValid() {
		return nil, E.New("invalid server address")
	}
	if serverAddr.Port == 0 {
		serverAddr.Port = 53
	}
	upstream := &UDPUpstream{
		newUpstreamAdapter(options, serverAddr),
		newTCPUpstream(options, serverAddr),
		options.Logger,
		512,
	}
	upstream.handler = upstream
	return upstream, nil
}

func (t *UDPUpstream) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	response, err := t.myUpstreamAdapter.Exchange(ctx, message)
	if err != nil {
		return nil, err
	}
	if response.Truncated {
		t.logger.InfoContext(ctx, "response truncated, retrying with TCP")
		return t.tcpUpstream.Exchange(ctx, message)
	}
	return response, nil
}

func (t *UDPUpstream) DialContext(ctx context.Context) (net.Conn, error) {
	return t.dialer.DialContext(ctx, "udp", t.serverAddr)
}

func (t *UDPUpstream) ReadMessage(conn net.Conn) (*dns.Msg, error) {
	buffer := buf.NewSize(t.udpSize)
	defer buffer.Release()
	_, err := buffer.ReadOnceFrom(conn)
	if err != nil {
		return nil, err
	}
	var message dns.Msg
	err = message.Unpack(buffer.Bytes())
	return &message, err
}

func (t *UDPUpstream) WriteMessage(conn net.Conn, message *dns.Msg) error {
	if edns0Opt := message.IsEdns0(); edns0Opt != nil {
		if udpSize := int(edns0Opt.UDPSize()); udpSize > t.udpSize {
			t.udpSize = udpSize
		}
	}
	buffer := buf.NewSize(1 + message.Len())
	defer buffer.Release()
	exMessage := *message
	exMessage.Compress = true
	rawMessage, err := exMessage.PackBuffer(buffer.FreeBytes())
	if err != nil {
		return err
	}
	return common.Error(conn.Write(rawMessage))
}
