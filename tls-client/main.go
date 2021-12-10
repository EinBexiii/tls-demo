package main

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"io/ioutil"
	"log"

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
	handshakeSuccess := doHanshake()

	if !handshakeSuccess {
		return
	}

}

func doHanshake() bool {
	certPool := x509.NewCertPool()

	caCert := contentToBytes(CA_CERT_PATH)
	valid := certPool.AppendCertsFromPEM(caCert) // check if cert is valid

	if !valid {
		log.Fatal("CaCert is not valid!")
		return false
	}

	cert, err := tls.X509KeyPair(contentToBytes(SERVER_CERT_PATH), contentToBytes(PRIV_KEY_PATH))
	// parses private key

	if err != nil {
		log.Fatal(err)
		return false
	}

	tlsConfig := &tls.Config{
		RootCAs:      certPool,
		Certificates: []tls.Certificate{cert},
	}

	connection, err := tls.Dial("tcp", HOST, tlsConfig)

	if err != nil {
		log.Fatal(err)
		return false
	}

	defer connection.Close()

	p256 := ecdh.Generic(elliptic.P256()) // key exchange

	clientPrivKey, clientPubKey, err := p256.GenerateKey(nil) //generate privatekey, publickey

	if err != nil {
		log.Fatal(err)
		return false
	}

	err = p256.Check(clientPubKey) // before we sending the pubkey to the server, we want to check if it's valid

	if err != nil {
		log.Fatal(err)
		return false
	}

	keyBytes, _ := encode(clientPubKey) // premaster secret

	packet := &HandshakePacket{packetType: HANDSHAKE_TYPE, data: keyBytes}
	encodedPacket, _ := encode(packet)

	_, err = connection.Write(encodedPacket)

	if err != nil {
		log.Fatal(err)
		return false
	}

	for { // listen to an answer from server
		buf := make([]byte, 1380) // we want to read 1380, cuz by default the ASA sets the TCP MSS option in the SYN packets to 1380
		_, err := connection.Read(buf)

		if err != nil {
			log.Fatal(err)
			return false
		}

		receivedPacket := &HandshakePacket{}
		_ = decode(receivedPacket, buf)

		if receivedPacket.packetType == HANDSHAKE_SUCCESS_TYPE {
			handshakePacket := &HandshakeSuccessPacket{}
			_ = decode(handshakePacket, receivedPacket.data)

			err = p256.Check(handshakePacket.ServerPublicKey)

			if err != nil {
				log.Fatal("PublicKey is not valid!")
				return false
			}

			SECRET = p256.ComputeSecret(clientPrivKey, handshakePacket.ServerPublicKey) // master-secret

			log.Printf("Handshake SUCCESS!")

			return true

		} else {
			log.Printf("Handshake failed!")
			return false // handshake failed
		}
	}
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
