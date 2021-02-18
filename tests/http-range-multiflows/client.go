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

type httpRange struct {
	Start uint
	End   uint
}

const step = 1000
const url = "http://127.0.0.1:8000/mqtt5_pub_jpeg.pcap"

func main() {

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
	myranges := []httpRange{
		{1000, 2000}, // out of order
		{0, 1000},    // order + resume previous
		{500, 1500},  // only overlap
		{1500, 2500}, // overlap + new data
		{5000, 6000}, // out of order
		{2500, 3500}, // order but no resume
		{4000, 5000}, // out of order insert in head
		{7000, 8000}, // out or order insert at tail
		{6000, 7000}, // out of order inster in the middle
		{3000, 4000}, // overlap + new data + resume multiple
	}

	filesize := 0

	for i := range myranges {
		req2, _ := http.NewRequest("GET", url, nil)
		req2.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", myranges[i].Start, myranges[i].End-1))
		resp2, _ := client.Do(req2)
		filesize, _ = strconv.Atoi(strings.Split(resp2.Header["Content-Range"][0], "/")[1])
		io.Copy(ioutil.Discard, resp2.Body)
		resp2.Body.Close()

		fmt.Printf("download %#+v %#+v\n", myranges[i].Start, step)
	}

	for o := 8000; o < filesize; o += step {
		req2, _ := http.NewRequest("GET", url, nil)
		req2.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", o, o+step-1))
		resp2, _ := client.Do(req2)
		io.Copy(ioutil.Discard, resp2.Body)
		resp2.Body.Close()
		fmt.Printf("download %#+v %#+v\n", o, step)
	}
}
