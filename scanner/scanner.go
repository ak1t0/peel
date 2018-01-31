package scanner

import (
	"bufio"
	"fmt"
	"golang.org/x/net/proxy"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

// Onion is a onion service
type Onion struct {
	Address          string
	Alive            bool
	WebServer        string
	WebServerVersion string
	FuzzURL          []string
	OS               string
	WebApp           string
}

// Onions is Onion slice
type Onions []Onion

// NewOnions is Onions constructor
func NewOnions(target []string) Onions {
	var onions Onions
	for _, v := range target {
		onions = append(onions, Onion{Address: v})
	}
	return onions
}

// ScanOnions control onion scanner
func ScanOnions(onions *Onions) {
	// set Tor option
	hostPort := "127.0.0.1:9050"
	p, err := proxy.SOCKS5("tcp", hostPort, nil, proxy.Direct)
	if err != nil {
		log.Println(err)
	}
	// semaphore for control whole program
	c := make(chan bool, 1)
	// only sync last goroutine
	wg := &sync.WaitGroup{}
	for i, onion := range *onions {
		c <- true
		wg.Add(1)
		go func(i int, onion Onion) {
			defer func() { <-c }()
			log.Println("Scan start " + onion.Address)
			scanOnion(&onion, &p)
			(*onions)[i] = onion
			wg.Done()
		}(i, onion)
	}
	wg.Wait()
}

// scanOnion scan onion service
func scanOnion(onion *Onion, p *proxy.Dialer) {
	client := http.DefaultClient
	client.Transport = &http.Transport{
		Dial: (*p).Dial,
	}
	response, err := client.Get(onion.Address)

	if err != nil {
		log.Println(err)
		return
	}
	(*onion).Alive = true
	checkServerHeader(response, onion)

	if onion.WebServer == "Unknown" {
		checkErrorPage(client, onion)
	}

	if onion.WebServer == "Apache" {
		fuzzApacheURL(client, onion)
	} else if onion.WebServer == "nginx" {
		//fuzznginxURL(client, onion)
	}

	checkWordPress(client, onion)
	fmt.Println(onion)
}

// checkServerHeader check leaked Server header
func checkServerHeader(response *http.Response, onion *Onion) {
	server := response.Header.Get("Server")
	if strings.Contains(server, "nginx") {
		onion.WebServer = "nginx"
		if strings.Contains(server, "Ubuntu") {
			onion.OS = "Ubuntu"
		}
		r := regexp.MustCompile(`\d.\d\d.\d`)
		if r.FindString(server) != "" {
			onion.WebServerVersion = r.FindString(server)
		}
	} else if strings.Contains(server, "Apache") {
		onion.WebServer = "Apache"
		if strings.Contains(server, "Ubuntu") {
			onion.OS = "Ubuntu"
		}
		r := regexp.MustCompile(`\d.\d.\d\d`)
		if r.FindString(server) != "" {
			onion.WebServerVersion = r.FindString(server)
		}
	} else {
		onion.WebServer = "Unknown"
	}

}

// fuzzApacheURL look for Apache exposed URL
func fuzzApacheURL(client *http.Client, onion *Onion) {
	var fuzz []string
	address := onion.Address
	s := bufio.NewScanner(strings.NewReader(apacheFuzz))
	for s.Scan() {
		fuzz = append(fuzz, address+s.Text())
	}
	// semaphore for scan goroutine
	c := make(chan bool, 4)
	wg := &sync.WaitGroup{}
	for _, v := range fuzz {
		c <- true
		wg.Add(1)
		go func(v string) {
			defer func() { <-c }()
			response, err := client.Get(v)
			if err != nil {
				fmt.Println(err)
				wg.Done()
				return
			}
			if response.StatusCode < 404 {
				fmt.Println("URL is found! : ", v)
				onion.FuzzURL = append(onion.FuzzURL, v)
			}
			wg.Done()
		}(v)

	}
	wg.Wait()

}

// checkErrorPage check leaked info in error page
func checkErrorPage(client *http.Client, onion *Onion) {
	response, err := client.Get(onion.Address + "/fuck")
	if err != nil {
		log.Println(err)
		return
	}
	defer response.Body.Close()
	body, _ := ioutil.ReadAll(response.Body)
	s := string(body)
	if strings.Contains(s, "nginx") {
		onion.WebServer = "nginx"
		if strings.Contains(s, "Ubuntu") {
			onion.OS = "Ubuntu"
		}
		r := regexp.MustCompile(`\d.\d\d.\d`)
		if r.FindString(s) != "" {
			onion.WebServerVersion = r.FindString(s)
		}
	} else if strings.Contains(s, "Apache") {
		onion.WebServer = "Apache"
		if strings.Contains(s, "Ubuntu") {
			onion.OS = "Ubuntu"
		}
		r := regexp.MustCompile(`\d.\d.\d\d`)
		if r.FindString(s) != "" {
			onion.WebServerVersion = r.FindString(s)
		}
	}
}

// checkWordPress look for WordPress exposed URL
// TODO: implement more smart checker because false positive is too many
func checkWordPress(client *http.Client, onion *Onion) {
	var fuzz []string
	address := onion.Address
	s := bufio.NewScanner(strings.NewReader(wpFuzz))
	for s.Scan() {
		fuzz = append(fuzz, address+s.Text())
	}
	// semaphore for scan goroutine
	c := make(chan bool, 3)
	wg := &sync.WaitGroup{}
	for _, v := range fuzz {
		c <- true
		wg.Add(1)
		go func(v string) {
			defer func() { <-c }()
			response, err := client.Get(v)
			if err != nil {
				fmt.Println(err)
				wg.Done()
				return
			}
			if response.StatusCode < 404 {
				fmt.Println("URL is found! : ", v)
				onion.FuzzURL = append(onion.FuzzURL, v)
				onion.WebApp = "WordPress"
			}
			wg.Done()
		}(v)

	}
	wg.Wait()
}

// fuzz list for apache
// https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web_Content/Apache.fuzz.txt
const apacheFuzz = `/.htaccess
/.htaccess.bak
/.htpasswd
/.meta
/.web
/apache/logs/access.log
/apache/logs/access_log
/apache/logs/error.log
/apache/logs/error_log
/httpd/logs/access.log
/httpd/logs/access_log
/httpd/logs/error.log
/httpd/logs/error_log
/logs/access.log
/logs/access.log
/logs/error.log
/logs/error_log
/access_log
/cgi
/cgi-bin
/cgi-pub
/cgi-script
/dummy
/error
/error_log
/htdocs
/httpd
/httpd.pid
/icons
/index.html
/logs
/manual
/phf
/printenv
/server-info
/server-status
/status
/test-cgi
/tmp
`

// fuzz list for WordPress
const wpFuzz = `/wp-content
/wp-admin
/wp-includes
`
