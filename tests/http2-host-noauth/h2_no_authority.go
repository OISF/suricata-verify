package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

const (
	clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	frameData     = 0x0
	frameHeaders  = 0x1
	frameRST      = 0x3
	frameSettings = 0x4
	frameGoAway   = 0x7

	flagEndStream  = 0x1
	flagEndHeaders = 0x4
	flagSettingsAck = 0x1
)

type frame struct {
	typeID   byte
	flags    byte
	streamID uint32
	payload  []byte
}

func writeFrame(w io.Writer, typeID, flags byte, streamID uint32, payload []byte) error {
	if len(payload) > 0xFFFFFF {
		return fmt.Errorf("payload too large: %d", len(payload))
	}
	var hdr [9]byte
	hdr[0] = byte(len(payload) >> 16)
	hdr[1] = byte(len(payload) >> 8)
	hdr[2] = byte(len(payload))
	hdr[3] = typeID
	hdr[4] = flags
	binary.BigEndian.PutUint32(hdr[5:], streamID&0x7FFFFFFF)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func readFrame(r io.Reader) (frame, error) {
	var hdr [9]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return frame{}, err
	}
	length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return frame{}, err
		}
	}
	return frame{
		typeID:   hdr[3],
		flags:    hdr[4],
		streamID: binary.BigEndian.Uint32(hdr[5:]) & 0x7FFFFFFF,
		payload:  payload,
	}, nil
}

func hpackInt(i int, prefixBits uint8, firstMask byte) []byte {
	maxPrefix := (1 << prefixBits) - 1
	if i < maxPrefix {
		return []byte{firstMask | byte(i)}
	}
	out := []byte{firstMask | byte(maxPrefix)}
	i -= maxPrefix
	for i >= 128 {
		out = append(out, byte(i%128+128))
		i /= 128
	}
	out = append(out, byte(i))
	return out
}

func hpackString(s string) []byte {
	// Huffman bit is 0; plain bytes follow.
	out := hpackInt(len(s), 7, 0x00)
	out = append(out, []byte(s)...)
	return out
}

func hpackLiteralNoIndexNewName(name, value string) []byte {
	// 0000xxxx with 4-bit prefix and index=0 means "new name".
	out := hpackInt(0, 4, 0x00)
	out = append(out, hpackString(name)...)
	out = append(out, hpackString(value)...)
	return out
}

func main() {
	addr := "127.0.0.1:8080"
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		log.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	bw := bufio.NewWriter(conn)

	// Send client connection preface.
	if _, err := bw.WriteString(clientPreface); err != nil {
		log.Fatalf("write preface: %v", err)
	}

	// Send initial SETTINGS frame.
	if err := writeFrame(bw, frameSettings, 0, 0, nil); err != nil {
		log.Fatalf("write settings: %v", err)
	}
	if err := bw.Flush(); err != nil {
		log.Fatalf("flush preface/settings: %v", err)
	}

	// Read frames until we receive server SETTINGS, then ACK it.
	seenServerSettings := false
	for !seenServerSettings {
		f, err := readFrame(conn)
		if err != nil {
			log.Fatalf("read initial frame: %v", err)
		}
		if f.typeID == frameSettings && (f.flags&flagSettingsAck) == 0 {
			seenServerSettings = true
		}
	}
	if err := writeFrame(bw, frameSettings, flagSettingsAck, 0, nil); err != nil {
		log.Fatalf("write settings ack: %v", err)
	}
	if err := bw.Flush(); err != nil {
		log.Fatalf("flush settings ack: %v", err)
	}

	// Build header block WITHOUT :authority.
	var hb bytes.Buffer
	hb.Write(hpackLiteralNoIndexNewName(":method", "GET"))
	hb.Write(hpackLiteralNoIndexNewName(":scheme", "http"))
	hb.Write(hpackLiteralNoIndexNewName(":path", "/"))
    //hb.Write(hpackLiteralNoIndexNewName(":authority", "tata"))
	hb.Write(hpackLiteralNoIndexNewName("host", "toto.host.com"))

	// Send request HEADERS on stream 1.
	if err := writeFrame(bw, frameHeaders, flagEndHeaders|flagEndStream, 1, hb.Bytes()); err != nil {
		log.Fatalf("write headers: %v", err)
	}
	if err := bw.Flush(); err != nil {
		log.Fatalf("flush request headers: %v", err)
	}

	fmt.Println("request sent (Host: toto, no :authority)")

	// Read response until stream 1 ends or connection closes.
	for {
		f, err := readFrame(conn)
		if err != nil {
			if err == io.EOF {
				fmt.Println("server closed connection")
				return
			}
			log.Fatalf("read response frame: %v", err)
		}

		switch f.typeID {
		case frameHeaders:
			if f.streamID != 1 {
				continue
			}
			fmt.Printf("received HEADERS frame (%d bytes)\n", len(f.payload))
			if (f.flags & flagEndStream) != 0 {
				return
			}
		case frameData:
			if f.streamID != 1 {
				continue
			}
			if len(f.payload) > 0 {
				if _, err := os.Stdout.Write(f.payload); err != nil {
					log.Fatalf("write data to stdout: %v", err)
				}
			}
			if (f.flags & flagEndStream) != 0 {
				fmt.Println()
				return
			}
		case frameRST:
			if f.streamID == 1 && len(f.payload) >= 4 {
				errCode := binary.BigEndian.Uint32(f.payload[:4])
				fmt.Printf("stream reset by server: 0x%08x\n", errCode)
				return
			}
		case frameGoAway:
			if len(f.payload) >= 8 {
				errCode := binary.BigEndian.Uint32(f.payload[4:8])
				debug := ""
				if len(f.payload) > 8 {
					debug = string(f.payload[8:])
				}
				fmt.Printf("GOAWAY received: err=0x%08x debug=%q\n", errCode, debug)
			} else {
				fmt.Println("GOAWAY received")
			}
			return
		}
	}
}
