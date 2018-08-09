package main

// Original copy from https://github.com/Scalingo/go-ssh-examples/blob/master/client.go
import (
	"fmt"
	"log"
	"os"
	"io/ioutil"
	// "net"
	// "reflect"
	// "crypto/x509"
	// "encoding/pem"


	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func init() {
	log.SetFlags(log.LUTC|log.Lmicroseconds)
}

func main() {
	log.Println(os.Args)
	if len(os.Args) != 5 {
		log.Fatalf("Usage: %s <user> <host:port> <password> <command>", os.Args[0])
	}

	client, session, err := connectToHost(os.Args[1], os.Args[2], os.Args[3])
	if err != nil {
		panic(err)
	}
	log.Println("Run:", os.Args[4])
	out, err := session.CombinedOutput(os.Args[4])
	if err != nil {
		log.Println("output:", out)
		panic(err)
	}
	log.Println("output:")
	fmt.Println(string(out))
	client.Close()
	log.Println("closed")
}

func connectToHost(user, host, password string) (*ssh.Client, *ssh.Session, error) {
	log.Println("hostkeys")
	hostKeyCallback, err := knownhosts.New("mlab4.lga0t.txt")
	if err != nil {
		return nil, nil, err
	}
	signer, err := readPrivateKey("f1024")
	if err != nil {
		return nil, nil, err
	}
	sshConfig := &ssh.ClientConfig{
		Config: ssh.Config{
			RekeyThreshold: 1024 * 8,
		},
		User: user,
		Auth: []ssh.AuthMethod{
			// ssh.Password(password)
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
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

	/*
	hostKey, err := parseHostKey()
	if err != nil {
		panic(err)
	}
	*/
	// Failing to match host key.
	// sshConfig.HostKeyCallback = ssh.FixedHostKey(hostKey)
	// sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	/*sshConfig.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fmt.Println("known", hostKey)
		fmt.Println("server", key)
		fmt.Println("type", reflect.TypeOf(key))
		return nil
	}*/

	log.Println("dial")
	client, err := ssh.Dial("tcp", host, sshConfig)
	if err != nil {
		return nil, nil, err
	}

	log.Println("new session")
	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, nil, err
	}

	return client, session, nil
}

func readPrivateKey(name string) (ssh.Signer, error) {
	pem, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, err
	}
	return signer, nil
}