package main

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"io/ioutil"
	"log"
	"net"

	"github.com/aead/ecdh"
)

const (
	CA_CERT_PATH     = "/path/to/go"
	SERVER_CERT_PATH = "/path/to/go"
	PRIV_KEY_PATH    = "/path/to/go"

	HOST = "127.0.0.1:443" // tls server

	HANDSHAKE_TYPE         = 0x1
	HANDSHAKE_SUCCESS_TYPE = 0x2
)

var (
	SECRET []byte
)

type HandshakePacket struct {
	packetType byte
	data       []byte
}

type HandshakeSuccessPacket struct {
	ServerPublicKey crypto.PublicKey
}

func main() {
	err := startTlsServer()

	if err != nil {
		log.Panic("Failed to start TLS-Server: %v", err)
	}
}

func startTlsServer() error {
	certPool := x509.NewCertPool()

	caCert := contentToBytes(CA_CERT_PATH)
	valid := certPool.AppendCertsFromPEM(caCert) // check if cert is valid

	if !valid {
		log.Fatal("CaCert is not valid!")
		return nil
	}

	cert, err := tls.X509KeyPair(contentToBytes(SERVER_CERT_PATH), contentToBytes(PRIV_KEY_PATH))
	// parses private key

	if err != nil {
		log.Fatal(err)
		return err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}

	connection, err := tls.Listen("tcp", ":443", tlsConfig)
	log.Print("Listen on port 443...")

	if err != nil {
		log.Fatal(err)
		return err
	}

	defer connection.Close()

	gob.Register(ecdh.Point())

	for {
		tlsConn, err := connection.Accept()

		if err != nil {
			log.Fatal(err)
			continue
		}
		go handle(tlsConn) //handle async cuz in production there are more than 1 client
	}
}

func handle(connection net.Conn) {
	defer connection.Close()

	buffer := make([]byte, 512) //client-hello message needs to have a length of 512 https://wiki.osdev.org/TLS_Handshake

	for {
		_, err := connection.Read(buffer)

		if err != nil {
			log.Fatal(err)
			break
		}

		packet := &HandshakePacket{}
		_ = decode(packet, buffer)

		if packet.packetType == HANDSHAKE_TYPE {
			err := handshake(connection, packet.data)

			if err != nil {
				log.Fatal("Handshake failed: %v", err)
				break
			}

			log.Printf("Handshake Success")
		}
	}

}

func handshake(connection net.Conn, data []byte) error {
	gob.Register(rsa.PublicKey{})

	clientPublicKey := &ecdh.Point{}
	_ = decode(clientPublicKey, data)

	p256 := ecdh.Generic(elliptic.P256())

	serverPrivKey, serverPubKey, err := p256.GenerateKey(nil) // generate priv and pubkey for server, for generating master secret for client and server

	if err != nil {
		log.Fatal(err)
		return err
	}

	handshakePacket := &HandshakeSuccessPacket{ServerPublicKey: serverPubKey}

	handshakePacketBytes, _ := encode(handshakePacket)

	packet := &HandshakePacket{packetType: HANDSHAKE_SUCCESS_TYPE, data: handshakePacketBytes}

	packetBytes, _ := encode(packet)

	_, err = connection.Write(packetBytes)

	SECRET = p256.ComputeSecret(serverPrivKey, clientPublicKey) // master-secret

	if err != nil {
		log.Fatal(err)
		return err
	}

	return nil
}

func contentToBytes(path string) []byte {
	b, _ := ioutil.ReadFile(path)
	return b
}

func encode(dataStructure interface{}) (encoded []byte, err error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	err = encoder.Encode(dataStructure)

	if err != nil {
		log.Printf("Error : %s", err)
		return nil, err
	}

	return buffer.Bytes(), nil
}

func decode(dataStructure interface{}, data []byte) error {
	buffer := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buffer)
	err := decoder.Decode(dataStructure)

	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}
