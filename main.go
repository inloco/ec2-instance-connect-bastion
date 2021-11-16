package main

import (
	"context"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2instanceconnect"
	"github.com/gliderlabs/ssh"
	xssh "golang.org/x/crypto/ssh"
)

func newSignerFromFile(sshHostKeyPath string) (xssh.Signer, error) {
	sshHostKey, err := os.ReadFile(sshHostKeyPath)
	if err != nil {
		return nil, err
	}

	signer, err := xssh.ParsePrivateKey(sshHostKey)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

func main() {
	var hostSigners []ssh.Signer
	if len(os.Args) == 2 {
		signer, err := newSignerFromFile(os.Args[1])
		if err != nil {
			log.Fatalln(err)
		}

		hostSigners = append(hostSigners, signer)
	}

	awsConfig, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Panic(err)
	}

	ec2Client := ec2.NewFromConfig(awsConfig)
	eicClient := ec2instanceconnect.NewFromConfig(awsConfig)

	server := &ssh.Server{
		Addr: ":2222",
		Handler: func(session ssh.Session) {
			log.Printf("Handler(%v)\n", session)
		},
		HostSigners: hostSigners,
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			log.Printf("PublicKeyHandler(_, %v)\n", key)
			return true
		},
		LocalPortForwardingCallback: func(ctx ssh.Context, destinationHost string, destinationPort uint32) bool {
			log.Printf("LocalPortForwardingCallback(_, %v, %v)\n", destinationHost, destinationPort)

			userInterface := ctx.Value(ssh.ContextKeyUser)
			if userInterface == nil {
				log.Println("ctxVal == nil")
				return false
			}

			user, ok := userInterface.(string)
			if !ok {
				log.Println("!ok")
				return false
			}

			publicKeyInterface := ctx.Value(ssh.ContextKeyPublicKey)
			if publicKeyInterface == nil {
				log.Println("ctxVal == nil")
				return false
			}

			publicKey, ok := publicKeyInterface.(xssh.PublicKey)
			if !ok {
				log.Println("!ok")
				return false
			}
			authorizedKey := xssh.MarshalAuthorizedKey(publicKey)

			var availabilityZone string
			var instanceId string
			for _, filterName := range []string{
				"addresses.private-ip-address",
				"addresses.private-dns-name",
				"association.public-ip",
				"association.public-dns-name",
			} {
				out, err := ec2Client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
					Filters: []types.Filter{
						types.Filter{
							Name: aws.String(filterName),
							Values: []string{
								destinationHost,
							},
						},
					},
				})
				if err != nil {
					log.Println(err)
					continue
				}

				enis := out.NetworkInterfaces
				if len(enis) != 1 {
					log.Println("len(enis) != 1")
					continue
				}
				eni := enis[0]

				az := eni.AvailabilityZone
				if az == nil {
					log.Println("az == nil")
					continue
				}

				a := eni.Attachment
				if a == nil {
					log.Println("a == nil")
					continue
				}

				ii := a.InstanceId
				if ii == nil {
					log.Println("ii == nil")
					continue
				}

				availabilityZone = aws.ToString(az)
				instanceId = aws.ToString(ii)
				break
			}

			out, err := eicClient.SendSSHPublicKey(ctx, &ec2instanceconnect.SendSSHPublicKeyInput{
				AvailabilityZone: aws.String(availabilityZone),
				InstanceId:       aws.String(instanceId),
				InstanceOSUser:   aws.String(user),
				SSHPublicKey:     aws.String(string(authorizedKey)),
			})
			if err != nil {
				log.Println(err)
				return false
			}
			if !out.Success {
				log.Println("!out.Success")
				return false
			}

			return true
		},
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"direct-tcpip": ssh.DirectTCPIPHandler,
			"session":      ssh.DefaultSessionHandler,
		},
	}

	log.Println("EC2 Instance Connect Bastion")
	log.Println(server.Addr)
	log.Fatalln(server.ListenAndServe())
}
