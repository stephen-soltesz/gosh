package main

// Original copy from https://github.com/Scalingo/go-ssh-examples/blob/master/client.go
import (
	"fmt"
	"log"
	"os"
	"net"
	"reflect"
	"crypto/x509"
	"encoding/pem"


	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatalf("Usage: %s <user> <host:port> <command>", os.Args[0])
	}

	client, session, err := connectToHost(os.Args[1], os.Args[2])
	if err != nil {
		panic(err)
	}
	out, err := session.CombinedOutput(os.Args[3])
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))
	client.Close()
}

func connectToHost(user, host string) (*ssh.Client, *ssh.Session, error) {
	var pass string
	fmt.Print("Password: ")
	fmt.Scanf("%s\n", &pass)

	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.Password(pass)},
		// HostKeyAlgorithms: []string{ssh.KeyAlgoRSA},
	}
	// ssh.FixedHostKey()
	// accepts an ssh.PublicKey
	// one of *rsa.PublicKey
	// TODO: how to deserialize an ssh public key?
	// 
	// $ ssh-keyscan -p 806  mlab3d.lga03.measurement-lab.org > host.txt
	// $ ssh-keygen -f mlab3d.lga03.pub -e -m pem > mlab3d.lga03.pem

	// Add user public key to the DRAC. to authenticate with private key.
	// https://www.dell.com/support/manuals/us/en/04/integrated-dell-remote-access-cntrllr-8-with-lifecycle-controller-v2.00.00.00/racadm_idrac_pub-v1/sshpkauth?guid=guid-be12abd1-4995-4fa3-b090-9cb41321b7a4&lang=en-us
	
	// TODO:
	// ssh/knownhosts.New -- https://godoc.org/golang.org/x/crypto/ssh/knownhosts#New
	// reads a know_hosts file to implement the HostKeyCallback function.
	// Same format as output from ssh-keyscan!

	hostKey, err := parseHostKey()
	if err != nil {
		panic(err)
	}
	// Failing to match host key.
	// sshConfig.HostKeyCallback = ssh.FixedHostKey(hostKey)
	// sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	sshConfig.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fmt.Println("known", hostKey)
		fmt.Println("server", key)
		fmt.Println("type", reflect.TypeOf(key))
		return nil
	}

	client, err := ssh.Dial("tcp", host, sshConfig)
	if err != nil {
		return nil, nil, err
	}

	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, nil, err
	}

	return client, session, nil
}

func parseHostKey() (ssh.PublicKey, error) {
	const pubPEM = `
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAtcUQEdN/eMglvpi9CTyHWZa0ehGRBoqZaD4Nvckl3WOYW88B94Qm
4MSMnon95oxUer1TV23Usrsq64XD8cxKazPibFA/hEcsWN4xPm9I7bBaar1BuKnS
9a/vZRRqXuC1pjRmbb3y16SfMNW+8O7yUsVy9JZP5I9HDpM+/3xrfSgV1iGYSMzw
lSFolimevEDbd6Mat6cHneyr7kmUrBeJkGJ1bWS04LzfMkay7/cYKLXH9jhEmweg
DY+6albuC1/3sVsOOdN2taWBJ2guFK3TbEYkrUxF1cKqIciSTJplywLpMoeac69b
EJ8PloqEII6mNAcWX2zAIPQMCcMA3Lt20QIDAQAB
-----END RSA PUBLIC KEY-----`
	
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		panic("failed to parse PEM block containing the public key")
	}
	
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}

	return ssh.NewPublicKey(pub)
}