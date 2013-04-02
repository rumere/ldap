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
//	NetworkConnectTimeout time.Duration // default 0 no timeout
//	ReadTimeout    time.Duration // default 0 no timeout
//	AbandonMessageOnReadTimeout bool // send abandon on a ReadTimeout (not for searches yet)
//	Network        string // default empty "tcp"
//	Addr           string // default empty
//
// A minimal connection...
//	ldap := NewLDAPConnection("localhost",389)
//  err := ldap.Connect() // returns the same conn passed but connected.
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
	chanResultsLock    sync.RWMutex
	chanProcessMessage chan *messagePacket
	chanProcessLock    sync.RWMutex
	chanMessageID      chan uint64
	connected          bool
}

type idAndChan struct {
	messageID uint64
	out       chan *ber.Packet
}

// Connect connects using information in LDAPConnection.
// LDAPConnection should be populated with connection information.
func (l *LDAPConnection) Connect() *Error {
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
	l.connected = true
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
	if l.Debug {
		fmt.Println("Starting Close().")
	}
	l.sendProcessMessage(&messagePacket{Op: MessageQuit})
	return nil
}

// Returns the next available messageID
func (l *LDAPConnection) nextMessageID() (messageID uint64, ok bool) {
	messageID, ok = <-l.chanMessageID
	if l.Debug {
		fmt.Printf("MessageID: %d, ok: %v\n", messageID, ok)
	}
	return
}

// StartTLS sends the command to start a TLS session and then creates a new TLS Client
func (l *LDAPConnection) startTLS() *Error {
	messageID, ok := l.nextMessageID()
	if !ok {
		return NewError(ErrorClosing, errors.New("MessageID channel is closed."))
	}

	if l.IsSSL {
		return NewError(ErrorNetwork, errors.New("Already encrypted"))
	}

	tlsRequest := encodeTLSRequest()
	packet, err := requestBuildPacket(messageID, tlsRequest, nil)

	if err != nil {
		return err
	}

	err = l.sendReqRespPacket(messageID, packet)
	if err != nil {
		return err
	}

	conn := tls.Client(l.conn, nil)
	stderr := conn.Handshake()
	if stderr != nil {
		return NewError(ErrorNetwork, stderr)
	}
	l.IsSSL = true
	l.conn = conn

	return nil
}

func encodeTLSRequest() (tlsRequest *ber.Packet) {
	tlsRequest = ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedRequest, nil, "Start TLS")
	tlsRequest.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimative, 0, "1.3.6.1.4.1.1466.20037", "TLS Extended Command"))
	return
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
	if l.Debug {
		fmt.Printf("sendMessage-> message_id: %d\n", message_id)
	}

	out = make(chan *ber.Packet)
	l.chanResultsLock.Lock()
	defer l.chanResultsLock.Unlock()
	if l.chanResults == nil {
		return nil, NewError(ErrorClosing, errors.New("l.chanResults is nil"))
	}
	l.chanResults[message_id] = out

	if l.Debug {
		fmt.Printf("Adding message_id: %d, out: %v to chanResults\n", message_id, out)
	}

	message_packet := &messagePacket{Op: MessageRequest, MessageID: message_id, Packet: p, Channel: out}
	l.sendProcessMessage(message_packet)
	return
}

func (l *LDAPConnection) processMessages() {
	defer l.closeAllChannels()

	var message_id uint64 = 1
	var message_packet *messagePacket

	for {
		select {
		case l.chanMessageID <- message_id:
			message_id++
		case message_packet = <-l.chanProcessMessage:
			switch message_packet.Op {
			case MessageQuit:
				// Close all channels, connection and quit
				// use chanProcessLock to stop sends and l.connected
				// to stop any future sends. 
				l.chanProcessLock.Lock()
				defer l.chanProcessLock.Unlock()
				l.connected = false
				// will shutdown reader.
				l.conn.Close()
				if l.Debug {
					fmt.Printf("Shutting down\n")
				}
				return
			case MessageRequest:
				// Add to message list and write to network
				if l.Debug {
					fmt.Printf("Sending message %d\n", message_packet.MessageID)
				}
				// l.chanResults[message_packet.MessageID] = message_packet.Channel
				buf := message_packet.Packet.Bytes()
				for len(buf) > 0 {
					n, err := l.conn.Write(buf)
					if err != nil {
						// Close all channels, connection and quit
						l.chanProcessLock.Lock()
						defer l.chanProcessLock.Unlock()
						l.connected = false
						l.conn.Close()
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
				func() {
					l.chanResultsLock.RLock()
					defer l.chanResultsLock.RUnlock()
					chanResult, ok := l.chanResults[message_packet.MessageID]

					if !ok {
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
				}()
			case MessageFinish:
				// Remove from message list
				if l.Debug {
					fmt.Printf("Finished message %d\n", message_packet.MessageID)
				}
				func() {
					l.chanResultsLock.Lock()
					defer l.chanResultsLock.Unlock()
					delete(l.chanResults, message_packet.MessageID)
				}()
			}
		}
	}
}

func (l *LDAPConnection) closeAllChannels() {
	l.chanResultsLock.Lock()
	defer l.chanResultsLock.Unlock()
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
		l.sendProcessMessage(message_packet)
	}
}

func (l *LDAPConnection) sendProcessMessage(message *messagePacket) {
	go func() {
		l.chanProcessLock.RLock()
		defer l.chanProcessLock.RUnlock()
		if l.connected {
			l.chanProcessMessage <- message
		}
	}()
}
