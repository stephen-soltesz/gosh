package main

// Original copy from https://github.com/Scalingo/go-ssh-examples/blob/master/client.go
import (
	"flag"
	"fmt"
	"github.com/stephen-soltesz/gosh/flagext"
	"log"
	"os"
	// "net"
	// "reflect"
	// "crypto/x509"
	// "encoding/pem"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var (
	fPrivateKey  flagext.FileBytes // private key used to authenticate with servers.
	fHostKeyFile string            // list of allowed known host keys.
	fPassword    string            // optional password if privateKey is empty.
	fUser        string            // user
	fHostname    string            // hostname
)

func init() {
	log.SetFlags(log.LUTC | log.Lmicroseconds)
	flag.Var(&fPrivateKey, "private-key", "Filename of private RSA key")
	flag.StringVar(&fHostKeyFile, "known-hosts", "", "Filename of known host keys")
	flag.StringVar(&fPassword, "password", "", "Password if private key is not given")
	flag.StringVar(&fUser, "user", "admin", "User to use when accessing DRAC")
	flag.StringVar(&fHostname, "hostname", "", "Hostname and port to access the DRAC")
}

func main() {
	flag.Parse()

	log.Println(os.Args)
	if len(os.Args) != 5 {
		log.Fatalf("Usage: %s [flags] <command>", os.Args[0])
	}

	client, err := connectToHost(fUser, fHostname, fPassword)
	if err != nil {
		panic(err)
	}
	defer client.Close()

	for _, arg := range flag.Args() {
		log.Println("new session")
		session, err := client.NewSession()
		if err != nil {
			panic(err)
		}

		log.Println("Run:", arg)
		out, err := session.CombinedOutput(arg)
		if err != nil {
			log.Println("output:", out)
			panic(err)
		}
		log.Println("output:")
		fmt.Println(string(out))
	}

	log.Println("closing")
}

func connectToHost(user, host, password string) (*ssh.Client, error) {
	log.Println("hostkeys")
	hostKeyCallback, err := knownhosts.New(fHostKeyFile)
	if err != nil {
		return nil, err
	}
	var authMethod ssh.AuthMethod
	if password != "" {
		authMethod = ssh.Password(password)
	} else {
		signer, err := ssh.ParsePrivateKey(fPrivateKey)
		if err != nil {
			return nil, err
		}
		authMethod = ssh.PublicKeys(signer)
	}

	sshConfig := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: hostKeyCallback,
	}
	// ssh.FixedHostKey()
	// accepts an ssh.PublicKey
	// one of *rsa.PublicKey
	// TODO: how to deserialize an ssh public key?
	//
//		Config: ssh.Config{
//			RekeyThreshold: 1024 * 8,
//		},

	// $ ssh-keyscan -p 806  mlab3d.lga03.measurement-lab.org > host.txt
	// $ ssh-keygen -f mlab3d.lga03.pub -e -m pem > mlab3d.lga03.pem
	// Add user public key to the DRAC. to authenticate with private key.
	// https://www.dell.com/support/manuals/us/en/04/integrated-dell-remote-access-cntrllr-8-with-lifecycle-controller-v2.00.00.00/racadm_idrac_pub-v1/sshpkauth?guid=guid-be12abd1-4995-4fa3-b090-9cb41321b7a4&lang=en-us

	// TODO:
	// read know_hosts file to implement the HostKeyCallback function.
	// ssh/knownhosts.New -- https://godoc.org/golang.org/x/crypto/ssh/knownhosts#New
	// Same format as output from ssh-keyscan!

	// Failing to match host key.
	// sshConfig.HostKeyCallback = ssh.FixedHostKey(hostKey)
	// sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	// sshConfig.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
	//	fmt.Println("known", hostKey)
	//	fmt.Println("server", key)
	//	fmt.Println("type", reflect.TypeOf(key))
	//	return nil
	// }

	// NOTE: sending a racadm command with more than 256 chars fails due to the
	// interpreter getting a partial string. Methods tried:
	// * session.CombinedOutput()
	// * ssh admin@drac.fqdn "racadm sshpkauth ..."
	// * echo "racadm sshpkauth ..." | ssh admin@drac.fqdn
    // Only the last method works. It is unknown whether that mechanism can be
    // simulated with the go ssh package.

	/*
	Work around the apparent 256-byte line limit using other methods:
        echo "racadm sshpkauth -i 2 -k 1 -t 'ssh-rsa <key>'" | ssh -p806 \
		    admin@mlab4d.lga0t.measurement-lab.org
	*/

	log.Println("dial")
	client, err := ssh.Dial("tcp", host, sshConfig)
	if err != nil {
		return nil, err
	}

	//	log.Println("new session")
	//	session, err := client.NewSession()
	//	if err != nil {
	//		client.Close()
	//		return nil, nil, err
	//	}

	return client, nil
}
