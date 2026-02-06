package main

import (
	"bytes"
	"fmt"
	"log"
	"strings"

	"crypto/hmac"
	"crypto/sha256"

	"filippo.io/age"

	pb "github.com/bishopfox/sliver/protobuf/sliverpb"
	"google.golang.org/protobuf/proto"

	"github.com/bishopfox/sliver/implant/sliver/cryptography"
)

var (
	agePublicKeyPrefix = "age1"
	ageMsgPrefix       = []byte("age-encryption.org/v1\n-> X25519 ")
)

// AgeEncrypt - Encrypt using Nacl Box
func AgeEncrypt(recipientPublicKey string, plaintext []byte) ([]byte, error) {
	if !strings.HasPrefix(recipientPublicKey, agePublicKeyPrefix) {
		recipientPublicKey = agePublicKeyPrefix + recipientPublicKey
	}
	recipient, err := age.ParseX25519Recipient(recipientPublicKey)

	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer([]byte{})
	stream, err := age.Encrypt(buf, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := stream.Write(plaintext); err != nil {
		return nil, err
	}
	if err := stream.Close(); err != nil {
		return nil, err
	}
	return bytes.TrimPrefix(buf.Bytes(), ageMsgPrefix), nil
}

func main() {
	// 模拟cryptography包中的RandomKey和NewCipherContext函数
	sKey := cryptography.RandomKey()
	fmt.Println("sKey:", sKey)
	fmt.Printf("%x\n", sKey)
	fmt.Printf("sKey length: %d\n", len(sKey))

	httpSessionInit := &pb.HTTPSessionInit{Key: sKey[:]}

	// 使用proto.Marshal序列化消息。
	data, err := proto.Marshal(httpSessionInit)
	if err != nil {
		log.Fatalf("Failed to marshal proto: %v", err)
	}

	// 打印序列化后的数据的长度和内容。
	fmt.Printf("Serialized data length: %d\n", len(data))
	fmt.Printf("Serialized data: %x\n", data)

	// Generate a new key pair
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		fmt.Println("Error generating key pair:", err)
		return
	}

	// Print the public key
	// fmt.Println("Public Key:", identity.Recipient().String())

	// Print the private key
	// fmt.Println("Private Key:", identity.String())

	Private := identity.String()
	privateDigest := sha256.New()
	privateDigest.Write([]byte(Private))
	fmt.Printf("Private Digest: %x\n", privateDigest.Sum(nil))
	fmt.Printf("Private Digest length: %d\n", len(privateDigest.Sum(nil)))

	mac := hmac.New(sha256.New, privateDigest.Sum(nil))
	mac.Write(data)
	fmt.Printf("mac: %x\n", mac.Sum(nil))
	fmt.Printf("mac length: %d\n", len(mac.Sum(nil)))

	result := append(mac.Sum(nil), data...)
	fmt.Println(len(result))

	recipientPublicKey := "age17nae35txdde4lje6ns0q5qtp5f4st9vqad8hm3z469lgxglmuuwsxj35my"
	ciphertext, err := AgeEncrypt(recipientPublicKey, append(mac.Sum(nil), data...))
	fmt.Printf("cipher: %d #### err: %s\n", len(ciphertext), err)
	fmt.Printf("cipher: %x\n", ciphertext)

	// Sender includes hash of it's implant specific peer public key
	Public := identity.Recipient().String()
	publicDigest := sha256.Sum256([]byte(Public))
	msg := make([]byte, 32+len(ciphertext))
	copy(msg, publicDigest[:])
	copy(msg[32:], ciphertext)
	fmt.Printf("msg: %x\n", msg)
	fmt.Print("msg length: ", len(msg), "\n")

}

// 34 + 32 + 32
