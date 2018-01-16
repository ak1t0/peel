package scanner

import (
	"fmt"
	"golang.org/x/net/proxy"
	"log"
	"net/http"
)

type Onion struct {
	Address string
	Alive   bool
}

type Onions []Onion

func NewOnions(target []string) Onions {
	var onions Onions
	for _, v := range target {
		onions = append(onions, Onion{Address: v})
	}
	return onions
}

var target = []string{"http://jbwocj4f64dkfiwv.onion"}

func Scan(onion Onion) {
	// set Tor option
	hostPort := "127.0.0.1:9050"
	p, err := proxy.SOCKS5("tcp", hostPort, nil, proxy.Direct)
	if err != nil {
		fmt.Println(err)
	}

	client := http.DefaultClient
	client.Transport = &http.Transport{
		Dial: p.Dial,
	}

	response, err := client.Get(onion.Address)

	if err != nil {
		log.Println(err)
	}
	fmt.Println(response)
}
