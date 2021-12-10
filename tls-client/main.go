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
	CA_CERT_PATH     = "/root/certs/ca.crt"
	SERVER_CERT_PATH = "/root/certs/cert.crt"
	PRIV_KEY_PATH    = "/root/certs/clientprivkey.pem"

	HOST = "127.0.0.1:443" // tls server

	HANDSHAKE_TYPE         = 0x1
	HANDSHAKE_SUCCESS_TYPE = 0x2
)

var (
	SECRET []byte
)

type HandshakePacket struct {
	PacketType byte
	Data       []byte
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
		log.Print("CaCert is not valid!")
		return false
	}

	cert, err := tls.X509KeyPair(contentToBytes(SERVER_CERT_PATH), contentToBytes(PRIV_KEY_PATH))
	// parses private key

	if err != nil {
		log.Print(err)
		return false
	}

	tlsConfig := &tls.Config{
		RootCAs:      certPool,
		Certificates: []tls.Certificate{cert},
	}

	connection, err := tls.Dial("tcp", HOST, tlsConfig)

	if err != nil {
		log.Print(err)
		return false
	}

	defer connection.Close()

	p256 := ecdh.Generic(elliptic.P256()) // key exchange

	clientPrivKey, clientPubKey, err := p256.GenerateKey(nil) //generate privatekey, publickey

	if err != nil {
		log.Print(err)
		return false
	}

	err = p256.Check(clientPubKey) // before we sending the pubkey to the server, we want to check if it's valid

	if err != nil {
		log.Print(err)
		return false
	}

	keyBytes, _ := encode(clientPubKey) // premaster secret

	packet := &HandshakePacket{PacketType: HANDSHAKE_TYPE, Data: keyBytes}
	encodedPacket, _ := encode(packet)

	_, err = connection.Write(encodedPacket)

	if err != nil {
		log.Print(err)
		return false
	}

	for { // listen to an answer from server
		buf := make([]byte, 1380) // we want to read 1380, cuz by default the ASA sets the TCP MSS option in the SYN packets to 1380
		_, err := connection.Read(buf)

		if err != nil {
			log.Print(err)
			return false
		}

		gob.Register(ecdh.Point{})

		receivedPacket := &HandshakePacket{}
		_ = decode(receivedPacket, buf)

		if receivedPacket.PacketType == HANDSHAKE_SUCCESS_TYPE {
			connection.Close() // close connection to avoid next read from server

			handshakePacket := &HandshakeSuccessPacket{}
			_ = decode(handshakePacket, receivedPacket.Data)

			err = p256.Check(handshakePacket.ServerPublicKey)

			if err != nil {
				log.Print("PublicKey is not valid!")
				return false
			}

			SECRET = p256.ComputeSecret(clientPrivKey, handshakePacket.ServerPublicKey) // master-secret
			log.Print("Handshake Success")
			log.Print(SECRET)
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
