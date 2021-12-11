package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"

	"github.com/aead/ecdh"
)

const (
	CA_CERT_PATH     = "/root/certs/ca.crt"
	SERVER_CERT_PATH = "/root/certs/server.crt"
	PRIV_KEY_PATH    = "/root/certs/server.pem"

	HOST     = "127.0.0.1:443" // tls server
	UDP_HOST = "127.0.0.1:8080"

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

	go func() {
		err := startTlsServer()
		if err != nil {
			log.Printf("Failed to start TLS-Server: %v", err)
			return
		}
	}()

	startUdpServer()
}

func startTlsServer() error {
	certPool := x509.NewCertPool()

	caCert := contentToBytes(CA_CERT_PATH)
	valid := certPool.AppendCertsFromPEM(caCert) // check if cert is valid

	if !valid {
		log.Print("CaCert is not valid!")
		return nil
	}

	cert, err := tls.X509KeyPair(contentToBytes(SERVER_CERT_PATH), contentToBytes(PRIV_KEY_PATH))
	// parses private key

	if err != nil {
		log.Print(err)
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
		log.Print(err)
		return err
	}

	defer connection.Close()

	gob.Register(ecdh.Point{})

	for {
		tlsConn, err := connection.Accept()

		if err != nil {
			log.Print(err)
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
			log.Print("Somethig went wrong: %v", err)
			break
		}

		packet := &HandshakePacket{}
		_ = decode(packet, buffer)

		if packet.PacketType == HANDSHAKE_TYPE {
			err := handshake(connection, packet.Data)

			if err != nil {
				log.Print("Handshake failed: %v", err)
				break
			}

			log.Printf("Handshake Success")
			break
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
		log.Print(err)
		return err
	}

	handshakePacket := &HandshakeSuccessPacket{ServerPublicKey: serverPubKey}

	handshakePacketBytes, _ := encode(handshakePacket)

	packet := &HandshakePacket{PacketType: HANDSHAKE_SUCCESS_TYPE, Data: handshakePacketBytes}

	packetBytes, _ := encode(packet)

	_, err = connection.Write(packetBytes)

	SECRET = p256.ComputeSecret(serverPrivKey, clientPublicKey) // master-secret

	if err != nil {
		log.Print(err)
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

func encryptWithKey(secret []byte, plainTextData []byte) (EncryptedData []byte, err error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	EncryptedData = aesgcm.Seal(nil, nonce, plainTextData, nil)
	EncryptedData = append(EncryptedData, nonce...)
	return EncryptedData, nil
}

func decryptWithKey(secret []byte, encryptedData []byte) (plainText []byte, err error) {
	nonce := encryptedData[len(encryptedData)-12:]
	encryptedData = encryptedData[:len(encryptedData)-12]
	block, err := aes.NewCipher(secret)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plainText, err = aesgcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func startUdpServer() {
	udpAddr, err := net.ResolveUDPAddr("udp4", UDP_HOST)

	if err != nil {
		log.Fatal(err)
	}

	ln, err := net.ListenUDP("udp", udpAddr)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("UDP server up and listening on port 8080")

	defer ln.Close()

	for {
		handleUdpConnection(ln)
	}
}

func handleUdpConnection(conn *net.UDPConn) {

	buffer := make([]byte, 1024)

	n, _, err := conn.ReadFromUDP(buffer)

	decryptedData, _ := decryptWithKey(SECRET, buffer[:n])

	fmt.Println("Received from UDP client :  " + string(decryptedData))

	if err != nil {
		log.Fatal(err)
	}
}
