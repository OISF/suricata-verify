package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func main() {
	url := "http://i.imgur.com/z4d4kWk.jpg"
	step := 10000

	tr := &http.Transport{
		//may not be needed
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     10,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
	}
	client := &http.Client{Transport: tr}

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", step-1))
	resp, err := client.Do(req)
	filesize, _ := strconv.Atoi(strings.Split(resp.Header["Content-Range"][0], "/")[1])
	fmt.Printf("%#+v %#+v\n", filesize, err)
	//cf https://github.com/golang/go/issues/26095
	io.Copy(ioutil.Discard, resp.Body)
	resp.Body.Close()

	for start := step; start < filesize; start += step {
		req2, _ := http.NewRequest("GET", url, nil)
		req2.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, start+step-1))
		resp2, _ := client.Do(req2)
		io.Copy(ioutil.Discard, resp2.Body)
		resp2.Body.Close()

		fmt.Printf("%#+v %#+v\n", start, step)
	}
}
