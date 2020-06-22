package trsa

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestCreateKeys(t *testing.T) {
	GenerateKeypair(1024)
	_, _, err := GenerateKeys(2048)
	if err != nil {
		t.Error(err.Error())
	}
}

func TestNewKeypair(t *testing.T) {
	var err error
	_, err = loadKey()
	if err != nil {
		t.Error(err.Error())
	}
}

func loadKey() (*Keypair, error) {
	publicKey, err := ioutil.ReadFile("./testData/publicKey")
	if err != nil {
		return nil, err
	}
	privateKey, err := ioutil.ReadFile("./testData/privateKey")
	if err != nil {
		return nil, err
	}
	keypair, err := NewKeypair(publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	return keypair, nil
}

func TestEncryptDecrypt(t *testing.T) {
	keypair, err := loadKey()
	if err != nil {
		t.Fatal(err.Error())
	}
	data := []byte(`This weekend I made great progress for building secure independent apps. 
		With t-secure-express I provide a module, to have RSA encrypted communication between 
		a js web client and your express application. Both client and server are using my trsa 
		library, that is based on node-forge. So it is easy, for both sites to create their 
		crypto material. Also, the for the server side provided middleware can get applied to 
		any new or existing app. To enable secure RSA encrypted communication, without the need 
		for bothersome and for some part expensive and deployment delaying https certificates.
		Using this tech, you can establish secure connections on your timeline. `)
	encrypted, err := keypair.Encrypt(data)
	if err != nil {
		t.Fatal(err.Error())
	}

	decrypted, err := keypair.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err.Error())
	}

	if bytes.Compare(decrypted, data) != 0 {
		t.Fatal(fmt.Sprint("unequal ", string(decrypted), "--", string(data)))
	}
}

func TestSignVerify(t *testing.T) {
	keypair, err := loadKey()
	if err != nil {
		t.Fatal(err.Error())
	}
	data := []byte(`This weekend I made great progress for building secure independent apps. 
		With t-secure-express I provide a module, to have RSA encrypted communication between 
		a js web client and your express application. Both client and server are using my trsa 
		library, that is based on node-forge. So it is easy, for both sites to create their 
		crypto material. Also, the for the server side provided middleware can get applied to 
		any new or existing app. To enable secure RSA encrypted communication, without the need 
		for bothersome and for some part expensive and deployment delaying https certificates.
		Using this tech, you can establish secure connections on your timeline. `)
	signature, err := keypair.Sign(data)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = keypair.Verify(data, signature)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestJsArtifacts(t *testing.T) {

	pubKey, err := ioutil.ReadFile("./testData/publicKey")
	if err != nil {
		t.Fatal(err.Error())
	}
	priKey, err := ioutil.ReadFile("./testData/privateKey")
	if err != nil {
		t.Fatal(err.Error())
	}
	testData, err := ioutil.ReadFile("./testData/data.txt")
	if err != nil {
		t.Fatal(err.Error())
	}
	testDataEncrypted, err := ioutil.ReadFile("./testData/data.txt.encrypted")
	if err != nil {
		t.Fatal(err.Error())
	}

	testDataSignature, err := ioutil.ReadFile("./testData/data.txt.signature")
	if err != nil {
		t.Fatal(err.Error())
	}

	rsa2, err := NewKeypair(pubKey, priKey)
	if err != nil {
		t.Fatal(err.Error())
	}

	decrypted, err := rsa2.Decrypt(testDataEncrypted)
	if err != nil {
		t.Fatal(err.Error())
	}

	if bytes.Compare(testData, decrypted) != 0 {
		t.Fatal(fmt.Sprint("unequal", string(testData), "--", string(decrypted)))
	}

	err = rsa2.Verify(testData, testDataSignature)
	if err != nil {
		t.Fatal(err.Error())
	}
}
