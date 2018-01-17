package scanner

import (
	"fmt"
	"golang.org/x/net/proxy"
	"log"
	"net/http"
	"strings"
)

type Onion struct {
	Address   string
	Alive     bool
	WebServer string
}

type Onions []Onion

func NewOnions(target []string) Onions {
	var onions Onions
	for _, v := range target {
		onions = append(onions, Onion{Address: v})
	}
	return onions
}

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
	defer response.Body.Close()

	if err != nil {
		log.Println(err)
	}
	onion.Alive = true
	checkServerHeader(response, &onion)
	fmt.Println(onion)
}

func checkServerHeader(response *http.Response, onion *Onion) {
	server := response.Header["Server"][0]
	if strings.Contains(server, "nginx") {
		onion.WebServer = "nginx"
	} else if strings.Contains(server, "Apache") {
		onion.WebServer = "Apache"
	} else {
		onion.WebServer = "Unknown"
	}

}
