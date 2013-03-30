// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package provides LDAP client functions.
package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/mavricknz/asn1-ber"
	"net"
	"sync"
	"time"
)

// Conn - LDAP Connection and also pre/post connect configuation
//	IsTLS bool // default false
//	IsSSL bool // default false
//	Debug bool // default false
//	ConnectTimeout time.Duration // default 0 no timeout (not available in 1.0)
//	ReadTimeout    time.Duration // default 0 no timeout
//	Network        string // default empty "tcp"
//	Addr           string // default empty
//
// A minimal connection...
//	conn := new(ldap.LDAPConnection)
//	conn.Network = "tcp"
//	conn.Addr    = "localhost:1389"
//
//	conn, err := ldap.DialUsingConn(conn) // returns the same conn passed but connected.
type LDAPConnection struct {
	IsTLS bool
	IsSSL bool
	Debug bool

	Addr                        string
	NetworkConnectTimeout       time.Duration
	ReadTimeout                 time.Duration
	AbandonMessageOnReadTimeout bool

	TlsConfig *tls.Config

	conn               net.Conn
	chanResults        map[uint64]chan *ber.Packet
	chanProcessMessage chan *messagePacket
	chanMessageID      chan uint64

	closeLock sync.RWMutex
}

// DialUsingConn connects to the given address on the given network using
// net.DialTimeout. SSL/startTLS can be enabled
// Conn should be populated with connection information.
func (l *LDAPConnection) Connect() *Error {
	if len(l.chanResults) > 0 || l.chanProcessMessage != nil || l.chanMessageID != nil {
		return NewError(ErrorInvalidArgument,
			errors.New("Connect: Connection already setup? Can't reuse."))
	}

	l.chanResults = map[uint64]chan *ber.Packet{}
	l.chanProcessMessage = make(chan *messagePacket)
	l.chanMessageID = make(chan uint64)

	if l.conn == nil {
		var c net.Conn
		var err error
		if l.NetworkConnectTimeout > 0 {
			c, err = net.DialTimeout("tcp", l.Addr, l.NetworkConnectTimeout)
		} else {
			c, err = net.Dial("tcp", l.Addr)
		}

		if err != nil {
			return NewError(ErrorNetwork, err)
		}

		if l.IsSSL {
			tlsConn := tls.Client(c, l.TlsConfig)
			err = tlsConn.Handshake()
			if err != nil {
				return NewError(ErrorNetwork, err)
			}
			l.conn = tlsConn
		} else {
			l.conn = c
		}
	}

	if l.IsTLS {
		err := l.startTLS()
		if err != nil {
			return NewError(ErrorNetwork, err)
		}
	} else {
		l.start()
	}

	return nil
}

// NewConn returns a new basic connection. Should start connection via
// Connect
func NewLDAPConnection(server string, port uint16) *LDAPConnection {
	return &LDAPConnection{
		Addr: fmt.Sprintf("%s:%d", server, port),
	}
}

func (l *LDAPConnection) start() {
	go l.reader()
	go l.processMessages()
}

// Close closes the connection.
func (l *LDAPConnection) Close() *Error {
	l.closeLock.Lock()
	defer l.closeLock.Unlock()

	l.sendProcessMessage(&messagePacket{Op: MessageQuit})

	if l.conn != nil {
		err := l.conn.Close()
		if err != nil {
			return NewError(ErrorNetwork, err)
		}
		// Don't nil conn, as reader() should be allowed to read
		// error. If nil, then panics as using nil struct.
		// l.conn = nil
	}
	return nil
}

// Returns the next available messageID
func (l *LDAPConnection) nextMessageID() (messageID uint64) {
	defer func() {
		if r := recover(); r != nil {
			messageID = 0
		}
	}()
	messageID = <-l.chanMessageID
	return
}

// StartTLS sends the command to start a TLS session and then creates a new TLS Client
func (l *LDAPConnection) startTLS() *Error {
	messageID := l.nextMessageID()

	if l.IsSSL {
		return NewError(ErrorNetwork, errors.New("Already encrypted"))
	}

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, messageID, "MessageID"))
	startTLS := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedRequest, nil, "Start TLS")
	startTLS.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimative, 0, "1.3.6.1.4.1.1466.20037", "TLS Extended Command"))
	packet.AppendChild(startTLS)
	if l.Debug {
		ber.PrintPacket(packet)
	}

	_, err := l.conn.Write(packet.Bytes())
	if err != nil {
		return NewError(ErrorNetwork, err)
	}

	packet, err = ber.ReadPacket(l.conn)
	if err != nil {
		return NewError(ErrorNetwork, err)
	}

	if l.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			return NewError(ErrorDebugging, err)
		}
		ber.PrintPacket(packet)
	}

	if packet.Children[1].Children[0].Value.(uint64) == 0 {
		conn := tls.Client(l.conn, nil)
		l.IsSSL = true
		l.conn = conn
	}

	return nil
}

const (
	MessageQuit     = 0
	MessageRequest  = 1
	MessageResponse = 2
	MessageFinish   = 3
)

type messagePacket struct {
	Op        int
	MessageID uint64
	Packet    *ber.Packet
	Channel   chan *ber.Packet
}

func (l *LDAPConnection) sendMessage(p *ber.Packet) (out chan *ber.Packet, err *Error) {
	message_id := p.Children[0].Value.(uint64)
	out = make(chan *ber.Packet)

	if l.chanProcessMessage == nil {
		err = NewError(ErrorNetwork, errors.New("Connection closed"))
		return
	}
	message_packet := &messagePacket{Op: MessageRequest, MessageID: message_id, Packet: p, Channel: out}
	l.sendProcessMessage(message_packet)
	return
}

func (l *LDAPConnection) processMessages() {
	defer l.closeAllChannels()
	//defer func() {
	//	if r := recover(); r != nil {
	//		fmt.Println("Recovered in processMessages", r)
	//		debug.PrintStack()
	//	}
	//}()
	var message_id uint64 = 1
	var message_packet *messagePacket
	for {
		select {
		case l.chanMessageID <- message_id:
			if l.conn == nil {
				return
			}
			message_id++
		case message_packet = <-l.chanProcessMessage:
			if l.conn == nil {
				return
			}
			switch message_packet.Op {
			case MessageQuit:
				// Close all channels and quit
				if l.Debug {
					fmt.Printf("Shutting down\n")
				}
				return
			case MessageRequest:
				// Add to message list and write to network
				if l.Debug {
					fmt.Printf("Sending message %d\n", message_packet.MessageID)
				}
				l.chanResults[message_packet.MessageID] = message_packet.Channel
				buf := message_packet.Packet.Bytes()
				for len(buf) > 0 {
					n, err := l.conn.Write(buf)
					if err != nil {
						if l.Debug {
							fmt.Printf("Error Sending Message: %s\n", err.Error())
						}
						return
					}
					if n == len(buf) {
						break
					}
					buf = buf[n:]
				}
			case MessageResponse:
				// Pass back to waiting goroutine
				if l.Debug {
					fmt.Printf("Receiving message %d\n", message_packet.MessageID)
				}
				chanResult := l.chanResults[message_packet.MessageID]
				if chanResult == nil {
					fmt.Printf("Unexpected Message Result (possible Abandon): %d , MessageID: %d\n", message_id, message_packet.MessageID)
					// TODO: Noisy when abandoning connections, as server can still send.
					// Some sort of limited Abandon list?
					//ber.PrintPacket(message_packet.Packet)
				} else {
					packetCopy := message_packet.Packet
					go func() {
						chanResult <- packetCopy
					}()
				}
			case MessageFinish:
				// Remove from message list
				if l.Debug {
					fmt.Printf("Finished message %d\n", message_packet.MessageID)
				}
				delete(l.chanResults, message_packet.MessageID)
			}
		}
	}
}

func (l *LDAPConnection) closeAllChannels() {
	l.closeLock.Lock()
	defer l.closeLock.Unlock()

	for MessageID, Channel := range l.chanResults {
		if l.Debug {
			fmt.Printf("Closing channel for MessageID %d\n", MessageID)
		}
		close(Channel)
		delete(l.chanResults, MessageID)
	}
	close(l.chanMessageID)
	l.chanMessageID = nil

	close(l.chanProcessMessage)
	l.chanProcessMessage = nil
}

func (l *LDAPConnection) finishMessage(MessageID uint64) {
	message_packet := &messagePacket{Op: MessageFinish, MessageID: MessageID}
	l.sendProcessMessage(message_packet)
}

func (l *LDAPConnection) reader() {
	defer l.Close()
	//defer func() {
	//	if r := recover(); r != nil {
	//		// There was an issue with the reader still running
	//		// while the l.conn had been closed and nil'ed.
	//		// Catch here, while investigating better way of
	//		// handling.
	//		// go test -test.cpu=2 ldaptests
	//		fmt.Println("Recovered in reader", r)
	//		debug.PrintStack()
	//	}
	//}()
	for {
		p, err := ber.ReadPacket(l.conn)
		if err != nil {
			if l.Debug {
				fmt.Printf("ldap.reader: %s\n", err.Error())
			}
			return
		}

		addLDAPDescriptions(p)

		message_id := p.Children[0].Value.(uint64)
		message_packet := &messagePacket{Op: MessageResponse, MessageID: message_id, Packet: p}

		if l.chanProcessMessage != nil {
			l.sendProcessMessage(message_packet)
		} else {
			fmt.Printf("ldap.reader: Cannot return message\n")
			return
		}
	}
}

func (l *LDAPConnection) sendProcessMessage(message *messagePacket) {
	go func() {
		l.closeLock.RLock()
		defer l.closeLock.RUnlock()

		if l.chanProcessMessage != nil {
			l.chanProcessMessage <- message
		}
	}()
}
