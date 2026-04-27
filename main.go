package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	version      = "0.1.0"
	handshakeLen = 64
	skipLen      = 8
	prekeyLen    = 32
	keyLen       = 32
	ivLen        = 16
	protoTagPos  = 56
	dcIdxPos     = 60

	protoAbridgedInt           = 0xefefefef
	protoIntermediateInt       = 0xeeeeeeee
	protoPaddedIntermediateInt = 0xdddddddd

	dcFailCooldown = 30 * time.Second
	wsFailTimeout  = 2 * time.Second
)

var (
	protoTagAbridged     = []byte{0xef, 0xef, 0xef, 0xef}
	protoTagIntermediate = []byte{0xee, 0xee, 0xee, 0xee}
	protoTagSecure       = []byte{0xdd, 0xdd, 0xdd, 0xdd}
	reservedStarts       = [][]byte{
		{0x48, 0x45, 0x41, 0x44},
		{0x50, 0x4f, 0x53, 0x54},
		{0x47, 0x45, 0x54, 0x20},
		{0xee, 0xee, 0xee, 0xee},
		{0xdd, 0xdd, 0xdd, 0xdd},
		{0x16, 0x03, 0x01, 0x02},
	}
)

type Config struct {
	Host                    string
	Port                    int
	Secret                  string
	DCRedirects             map[int]string
	BufferSize              int
	PoolSize                int
	FallbackCFProxy         bool
	FallbackCFProxyPriority bool
	FallbackCFProxyDomain   string
	StatsFile               string
	Verbose                 bool
}

type Stats struct {
	ConnectionsTotal       atomic.Int64 `json:"connections_total"`
	ConnectionsActive      atomic.Int64 `json:"connections_active"`
	ConnectionsWS          atomic.Int64 `json:"connections_ws"`
	ConnectionsTCPFallback atomic.Int64 `json:"connections_tcp_fallback"`
	ConnectionsCFProxy     atomic.Int64 `json:"connections_cfproxy"`
	ConnectionsBad         atomic.Int64 `json:"connections_bad"`
	WSErrors               atomic.Int64 `json:"ws_errors"`
	BytesUp                atomic.Int64 `json:"bytes_up"`
	BytesDown              atomic.Int64 `json:"bytes_down"`
	PoolHits               atomic.Int64 `json:"pool_hits"`
	PoolMisses             atomic.Int64 `json:"pool_misses"`
}

type Server struct {
	cfg         Config
	secret      []byte
	stats       *Stats
	pool        *WSPool
	blacklistMu sync.Mutex
	wsBlacklist map[dcKey]bool
	failUntil   map[dcKey]time.Time
	debug       *log.Logger
	info        *log.Logger
}

type dcKey struct {
	DC      int
	IsMedia bool
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		log.Fatal(err)
	}
	secret, err := hex.DecodeString(cfg.Secret)
	if err != nil || len(secret) != 16 {
		log.Fatal("secret must be exactly 32 hex characters")
	}

	info := log.New(os.Stdout, "", log.LstdFlags)
	debugOut := io.Discard
	if cfg.Verbose {
		debugOut = os.Stdout
	}
	s := &Server{
		cfg:         cfg,
		secret:      secret,
		stats:       &Stats{},
		wsBlacklist: make(map[dcKey]bool),
		failUntil:   make(map[dcKey]time.Time),
		debug:       log.New(debugOut, "DEBUG ", log.LstdFlags),
		info:        info,
	}
	s.pool = NewWSPool(cfg.PoolSize, s)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := s.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func parseFlags() (Config, error) {
	var dcIPs multiFlag
	cfg := Config{
		Host:                    "127.0.0.1",
		Port:                    1443,
		DCRedirects:             map[int]string{2: "149.154.167.220", 4: "149.154.167.220"},
		BufferSize:              256 * 1024,
		PoolSize:                4,
		FallbackCFProxy:         false,
		FallbackCFProxyPriority: true,
		FallbackCFProxyDomain:   "",
		StatsFile:               "/var/log/tg-ws-proxy/stats.json",
	}
	flag.StringVar(&cfg.Host, "host", cfg.Host, "listen host")
	flag.IntVar(&cfg.Port, "port", cfg.Port, "listen port")
	flag.StringVar(&cfg.Secret, "secret", "", "32 hex chars")
	flag.Var(&dcIPs, "dc-ip", "target DC IP, e.g. 2:149.154.167.220; repeatable")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "debug logging")
	flag.BoolVar(&cfg.Verbose, "v", false, "debug logging")
	bufKB := flag.Int("buf-kb", 256, "socket buffer size in KB")
	flag.IntVar(&cfg.PoolSize, "pool-size", cfg.PoolSize, "idle WSS pool size per DC")
	flag.StringVar(&cfg.FallbackCFProxyDomain, "cfproxy-domain", cfg.FallbackCFProxyDomain, "Cloudflare fallback base domain")
	noCF := flag.Bool("no-cfproxy", false, "disable Cloudflare fallback")
	flag.BoolVar(&cfg.FallbackCFProxyPriority, "cfproxy-priority", cfg.FallbackCFProxyPriority, "try Cloudflare fallback before TCP fallback")
	flag.StringVar(&cfg.StatsFile, "stats-file", cfg.StatsFile, "stats JSON path")
	flag.Parse()

	cfg.BufferSize = max(4, *bufKB) * 1024
	cfg.FallbackCFProxyDomain = strings.TrimSpace(cfg.FallbackCFProxyDomain)
	cfg.FallbackCFProxy = !*noCF && cfg.FallbackCFProxyDomain != ""
	if len(dcIPs) > 0 {
		redirects, err := parseDCIPs(dcIPs)
		if err != nil {
			return cfg, err
		}
		cfg.DCRedirects = redirects
	}
	if cfg.Secret == "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return cfg, err
		}
		cfg.Secret = hex.EncodeToString(raw)
		log.Printf("Generated secret: %s", cfg.Secret)
	}
	if len(cfg.Secret) != 32 {
		return cfg, fmt.Errorf("secret must be exactly 32 hex characters")
	}
	if _, err := hex.DecodeString(cfg.Secret); err != nil {
		return cfg, fmt.Errorf("secret must be valid hex: %w", err)
	}
	return cfg, nil
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func parseDCIPs(entries []string) (map[int]string, error) {
	out := make(map[int]string, len(entries))
	for _, entry := range entries {
		left, right, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("invalid --dc-ip %q, expected DC:IP", entry)
		}
		dc, err := strconv.Atoi(left)
		if err != nil || net.ParseIP(right) == nil {
			return nil, fmt.Errorf("invalid --dc-ip %q", entry)
		}
		out[dc] = right
	}
	return out, nil
}

func (s *Server) Run(ctx context.Context) error {
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	linkHost := linkHost(s.cfg.Host)
	tgLink := fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=dd%s", linkHost, s.cfg.Port, s.cfg.Secret)
	s.info.Println(strings.Repeat("=", 60))
	s.info.Printf("Telegram MTProto WS Bridge Proxy Go v%s", version)
	s.info.Printf("Listening on   %s", addr)
	s.info.Printf("Secret:        %s", s.cfg.Secret)
	s.info.Println("Target DC IPs:")
	for _, dc := range sortedDCs(s.cfg.DCRedirects) {
		s.info.Printf("  DC%d: %s", dc, s.cfg.DCRedirects[dc])
	}
	if s.cfg.FallbackCFProxy {
		prio := "CF first"
		if !s.cfg.FallbackCFProxyPriority {
			prio = "TCP first"
		}
		s.info.Printf("CF proxy:      %s (%s)", s.cfg.FallbackCFProxyDomain, prio)
	}
	s.info.Printf("Connect link:  %s", tgLink)
	s.info.Println(strings.Repeat("=", 60))

	go s.logStats(ctx)
	s.pool.Warmup(ctx, s.cfg.DCRedirects)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.info.Printf("accept failed: %v", err)
			continue
		}
		_ = setTCPOptions(conn, s.cfg.BufferSize)
		go s.handleClient(conn)
	}
}

func (s *Server) handleClient(conn net.Conn) {
	s.stats.ConnectionsTotal.Add(1)
	s.stats.ConnectionsActive.Add(1)
	defer s.stats.ConnectionsActive.Add(-1)
	defer conn.Close()

	label := conn.RemoteAddr().String()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	handshake := make([]byte, handshakeLen)
	if _, err := io.ReadFull(conn, handshake); err != nil {
		s.debug.Printf("[%s] client disconnected before handshake: %v", label, err)
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	result, ok := tryHandshake(handshake, s.secret)
	if !ok {
		s.stats.ConnectionsBad.Add(1)
		s.debug.Printf("[%s] bad handshake", label)
		_, _ = io.Copy(io.Discard, conn)
		return
	}
	protoInt := uint32(protoAbridgedInt)
	if bytes.Equal(result.ProtoTag, protoTagIntermediate) {
		protoInt = uint32(protoIntermediateInt)
	} else if bytes.Equal(result.ProtoTag, protoTagSecure) {
		protoInt = uint32(protoPaddedIntermediateInt)
	}
	dcIdx := result.DC
	if result.IsMedia {
		dcIdx = -result.DC
	}
	relayInit, err := generateRelayInit(result.ProtoTag, int16(dcIdx))
	if err != nil {
		s.info.Printf("[%s] relay init failed: %v", label, err)
		return
	}

	cltDecryptor, cltEncryptor, tgEncryptor, tgDecryptor, err := buildCiphers(result.DecPrekeyIV, relayInit, s.secret)
	if err != nil {
		s.info.Printf("[%s] cipher setup failed: %v", label, err)
		return
	}

	key := dcKey{DC: result.DC, IsMedia: result.IsMedia}
	mediaTag := ""
	if result.IsMedia {
		mediaTag = " media"
	}
	target, inConfig := s.cfg.DCRedirects[result.DC]
	if !inConfig || s.isBlacklisted(key) {
		if !inConfig {
			s.info.Printf("[%s] DC%d not in config -> fallback", label, result.DC)
		} else {
			s.info.Printf("[%s] DC%d%s WS blacklisted -> fallback", label, result.DC, mediaTag)
		}
		s.doFallback(conn, relayInit, label, result.DC, result.IsMedia, protoInt, cltDecryptor, cltEncryptor, tgEncryptor, tgDecryptor)
		return
	}

	now := time.Now()
	wsTimeout := 10 * time.Second
	if until, ok := s.getFailUntil(key); ok && now.Before(until) {
		wsTimeout = wsFailTimeout
	}
	domains := wsDomains(result.DC, result.IsMedia)

	ws := s.pool.Get(ctxWithTimeout(12*time.Second), key, target, domains)
	if ws != nil {
		s.info.Printf("[%s] DC%d%s -> pool hit via %s", label, result.DC, mediaTag, target)
	} else {
		allRedirects := true
		gotRedirect := false
		for _, domain := range domains {
			s.info.Printf("[%s] DC%d%s -> wss://%s/apiws via %s", label, result.DC, mediaTag, domain, target)
			c, err := ConnectWS(target, domain, "/apiws", wsTimeout)
			if err == nil {
				ws = c
				allRedirects = false
				break
			}
			s.stats.WSErrors.Add(1)
			var hsErr *WSHandshakeError
			if errors.As(err, &hsErr) && hsErr.IsRedirect() {
				gotRedirect = true
				s.info.Printf("[%s] DC%d%s got %d from %s -> %s", label, result.DC, mediaTag, hsErr.StatusCode, domain, hsErr.Location)
				continue
			}
			allRedirects = false
			s.info.Printf("[%s] DC%d%s WS connect failed: %v", label, result.DC, mediaTag, err)
		}
		if ws == nil {
			if gotRedirect && allRedirects {
				s.setBlacklisted(key)
				s.info.Printf("[%s] DC%d%s blacklisted for WS (all redirects)", label, result.DC, mediaTag)
			} else {
				s.setFailUntil(key, now.Add(dcFailCooldown))
			}
			s.doFallback(conn, relayInit, label, result.DC, result.IsMedia, protoInt, cltDecryptor, cltEncryptor, tgEncryptor, tgDecryptor)
			return
		}
	}

	s.clearFailUntil(key)
	s.stats.ConnectionsWS.Add(1)
	splitter := NewMsgSplitter(relayInit, protoInt)
	if err := ws.Send(relayInit); err != nil {
		_ = ws.Close()
		return
	}
	s.bridgeWS(conn, ws, label, result.DC, result.IsMedia, cltDecryptor, cltEncryptor, tgEncryptor, tgDecryptor, splitter)
}

func (s *Server) doFallback(conn net.Conn, relayInit []byte, label string, dc int, isMedia bool, protoInt uint32, cltDec, cltEnc, tgEnc, tgDec cipher.Stream) {
	methods := []string{"tcp"}
	if s.cfg.FallbackCFProxy && s.cfg.FallbackCFProxyPriority {
		methods = []string{"cf", "tcp"}
	} else if s.cfg.FallbackCFProxy {
		methods = []string{"tcp", "cf"}
	}
	for _, method := range methods {
		if method == "cf" {
			if s.cfFallback(conn, relayInit, label, dc, isMedia, protoInt, cltDec, cltEnc, tgEnc, tgDec) {
				return
			}
			continue
		}
		if ip, ok := defaultDCIPs[dc]; ok {
			mediaTag := ""
			if isMedia {
				mediaTag = " media"
			}
			s.info.Printf("[%s] DC%d%s -> TCP fallback to %s:443", label, dc, mediaTag, ip)
			if s.tcpFallback(conn, ip, relayInit, label, dc, isMedia, cltDec, cltEnc, tgEnc, tgDec) {
				return
			}
		}
	}
}

func (s *Server) cfFallback(conn net.Conn, relayInit []byte, label string, dc int, isMedia bool, protoInt uint32, cltDec, cltEnc, tgEnc, tgDec cipher.Stream) bool {
	if s.cfg.FallbackCFProxyDomain == "" {
		return false
	}
	domain := fmt.Sprintf("kws%d.%s", dc, s.cfg.FallbackCFProxyDomain)
	mediaTag := ""
	if isMedia {
		mediaTag = " media"
	}
	s.info.Printf("[%s] DC%d%s -> CF proxy wss://%s/apiws", label, dc, mediaTag, domain)
	ws, err := ConnectWS(domain, domain, "/apiws", 10*time.Second)
	if err != nil {
		s.info.Printf("[%s] DC%d%s CF proxy failed: %v", label, dc, mediaTag, err)
		return false
	}
	s.stats.ConnectionsCFProxy.Add(1)
	if err := ws.Send(relayInit); err != nil {
		_ = ws.Close()
		return false
	}
	s.bridgeWS(conn, ws, label, dc, isMedia, cltDec, cltEnc, tgEnc, tgDec, NewMsgSplitter(relayInit, protoInt))
	return true
}

func (s *Server) tcpFallback(conn net.Conn, ip string, relayInit []byte, label string, dc int, isMedia bool, cltDec, cltEnc, tgEnc, tgDec cipher.Stream) bool {
	remote, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), 10*time.Second)
	if err != nil {
		s.info.Printf("[%s] TCP fallback failed: %v", label, err)
		return false
	}
	_ = setTCPOptions(remote, s.cfg.BufferSize)
	s.stats.ConnectionsTCPFallback.Add(1)
	if err := writeFull(remote, relayInit); err != nil {
		_ = remote.Close()
		return false
	}
	s.bridgeTCP(conn, remote, cltDec, cltEnc, tgEnc, tgDec)
	return true
}

func (s *Server) bridgeWS(client net.Conn, ws *RawWebSocket, label string, dc int, isMedia bool, cltDec, cltEnc, tgEnc, tgDec cipher.Stream, splitter *MsgSplitter) {
	defer ws.Close()
	done := make(chan struct{}, 2)
	start := time.Now()
	var upBytes, downBytes, upPackets, downPackets atomic.Int64

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 64*1024)
		for {
			n, err := client.Read(buf)
			if n > 0 {
				chunk := append([]byte(nil), buf[:n]...)
				s.stats.BytesUp.Add(int64(n))
				upBytes.Add(int64(n))
				upPackets.Add(1)
				cltDec.XORKeyStream(chunk, chunk)
				tgEnc.XORKeyStream(chunk, chunk)
				parts := [][]byte{chunk}
				if splitter != nil {
					parts = splitter.Split(chunk)
					if len(parts) == 0 {
						continue
					}
				}
				for _, part := range parts {
					if err := ws.Send(part); err != nil {
						return
					}
				}
			}
			if err != nil {
				if splitter != nil {
					for _, tail := range splitter.Flush() {
						_ = ws.Send(tail)
					}
				}
				return
			}
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		for {
			data, err := ws.Recv()
			if err != nil {
				return
			}
			s.stats.BytesDown.Add(int64(len(data)))
			downBytes.Add(int64(len(data)))
			downPackets.Add(1)
			tgDec.XORKeyStream(data, data)
			cltEnc.XORKeyStream(data, data)
			if err := writeFull(client, data); err != nil {
				return
			}
		}
	}()

	<-done
	_ = client.Close()
	_ = ws.Close()
	mediaTag := ""
	if isMedia {
		mediaTag = "m"
	}
	s.info.Printf("[%s] DC%d%s WS session closed: ^%s (%d pkts) v%s (%d pkts) in %.1fs",
		label, dc, mediaTag, humanBytes(upBytes.Load()), upPackets.Load(), humanBytes(downBytes.Load()), downPackets.Load(), time.Since(start).Seconds())
}

func (s *Server) bridgeTCP(client net.Conn, remote net.Conn, cltDec, cltEnc, tgEnc, tgDec cipher.Stream) {
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		copyReencrypt(remote, client, cltDec, tgEnc, &s.stats.BytesUp)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		copyReencrypt(client, remote, tgDec, cltEnc, &s.stats.BytesDown)
	}()
	<-done
	_ = client.Close()
	_ = remote.Close()
}

func copyReencrypt(dst net.Conn, src net.Conn, dec cipher.Stream, enc cipher.Stream, counter *atomic.Int64) {
	buf := make([]byte, 64*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			counter.Add(int64(n))
			dec.XORKeyStream(chunk, chunk)
			enc.XORKeyStream(chunk, chunk)
			if werr := writeFull(dst, chunk); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func writeFull(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

type handshakeResult struct {
	DC          int
	IsMedia     bool
	ProtoTag    []byte
	DecPrekeyIV []byte
}

func tryHandshake(handshake []byte, secret []byte) (handshakeResult, bool) {
	decPrekeyIV := append([]byte(nil), handshake[skipLen:skipLen+prekeyLen+ivLen]...)
	decPrekey := decPrekeyIV[:prekeyLen]
	decIV := decPrekeyIV[prekeyLen:]
	sum := sha256.Sum256(append(append([]byte(nil), decPrekey...), secret...))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return handshakeResult{}, false
	}
	dec := cipher.NewCTR(block, decIV)
	decrypted := append([]byte(nil), handshake...)
	dec.XORKeyStream(decrypted, decrypted)
	tag := decrypted[protoTagPos : protoTagPos+4]
	if !bytes.Equal(tag, protoTagAbridged) && !bytes.Equal(tag, protoTagIntermediate) && !bytes.Equal(tag, protoTagSecure) {
		return handshakeResult{}, false
	}
	dcIdx := int(int16(binary.LittleEndian.Uint16(decrypted[dcIdxPos : dcIdxPos+2])))
	dc := dcIdx
	isMedia := dcIdx < 0
	if dc < 0 {
		dc = -dc
	}
	return handshakeResult{DC: dc, IsMedia: isMedia, ProtoTag: append([]byte(nil), tag...), DecPrekeyIV: decPrekeyIV}, true
}

func generateRelayInit(protoTag []byte, dcIdx int16) ([]byte, error) {
	rnd := make([]byte, handshakeLen)
	for {
		if _, err := rand.Read(rnd); err != nil {
			return nil, err
		}
		if rnd[0] == 0xef || bytes.Equal(rnd[4:8], []byte{0, 0, 0, 0}) {
			continue
		}
		bad := false
		for _, reserved := range reservedStarts {
			if bytes.Equal(rnd[:4], reserved) {
				bad = true
				break
			}
		}
		if !bad {
			break
		}
	}
	block, err := aes.NewCipher(rnd[skipLen : skipLen+prekeyLen])
	if err != nil {
		return nil, err
	}
	enc := cipher.NewCTR(block, rnd[skipLen+prekeyLen:skipLen+prekeyLen+ivLen])
	encryptedFull := append([]byte(nil), rnd...)
	enc.XORKeyStream(encryptedFull, encryptedFull)
	tailPlain := make([]byte, 8)
	copy(tailPlain, protoTag)
	binary.LittleEndian.PutUint16(tailPlain[4:6], uint16(dcIdx))
	if _, err := rand.Read(tailPlain[6:8]); err != nil {
		return nil, err
	}
	result := append([]byte(nil), rnd...)
	for i := 0; i < 8; i++ {
		keystream := encryptedFull[protoTagPos+i] ^ rnd[protoTagPos+i]
		result[protoTagPos+i] = tailPlain[i] ^ keystream
	}
	return result, nil
}

func buildCiphers(clientPrekeyIV, relayInit, secret []byte) (cipher.Stream, cipher.Stream, cipher.Stream, cipher.Stream, error) {
	cltDecKeyHash := sha256.Sum256(append(append([]byte(nil), clientPrekeyIV[:prekeyLen]...), secret...))
	cltDec, err := newCTR(cltDecKeyHash[:], clientPrekeyIV[prekeyLen:])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	reversedClient := reverseCopy(clientPrekeyIV)
	cltEncKeyHash := sha256.Sum256(append(append([]byte(nil), reversedClient[:prekeyLen]...), secret...))
	cltEnc, err := newCTR(cltEncKeyHash[:], reversedClient[prekeyLen:])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	zero := make([]byte, 64)
	cltDec.XORKeyStream(zero, zero)

	relayEncKey := relayInit[skipLen : skipLen+prekeyLen]
	relayEncIV := relayInit[skipLen+prekeyLen : skipLen+prekeyLen+ivLen]
	tgEnc, err := newCTR(relayEncKey, relayEncIV)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	relayDecPrekeyIV := reverseCopy(relayInit[skipLen : skipLen+prekeyLen+ivLen])
	tgDec, err := newCTR(relayDecPrekeyIV[:keyLen], relayDecPrekeyIV[keyLen:])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	zero = make([]byte, 64)
	tgEnc.XORKeyStream(zero, zero)
	return cltDec, cltEnc, tgEnc, tgDec, nil
}

func newCTR(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func reverseCopy(in []byte) []byte {
	out := make([]byte, len(in))
	for i := range in {
		out[i] = in[len(in)-1-i]
	}
	return out
}

type MsgSplitter struct {
	dec       cipher.Stream
	proto     uint32
	cipherBuf []byte
	plainBuf  []byte
	disabled  bool
}

func NewMsgSplitter(relayInit []byte, proto uint32) *MsgSplitter {
	dec, err := newCTR(relayInit[8:40], relayInit[40:56])
	if err != nil {
		return nil
	}
	zero := make([]byte, 64)
	dec.XORKeyStream(zero, zero)
	return &MsgSplitter{dec: dec, proto: proto}
}

func (m *MsgSplitter) Split(chunk []byte) [][]byte {
	if m == nil || len(chunk) == 0 {
		return nil
	}
	if m.disabled {
		return [][]byte{chunk}
	}
	m.cipherBuf = append(m.cipherBuf, chunk...)
	plain := append([]byte(nil), chunk...)
	m.dec.XORKeyStream(plain, plain)
	m.plainBuf = append(m.plainBuf, plain...)
	var parts [][]byte
	for len(m.cipherBuf) > 0 {
		packetLen, ready := m.nextPacketLen()
		if !ready {
			break
		}
		if packetLen <= 0 {
			parts = append(parts, append([]byte(nil), m.cipherBuf...))
			m.cipherBuf = nil
			m.plainBuf = nil
			m.disabled = true
			break
		}
		parts = append(parts, append([]byte(nil), m.cipherBuf[:packetLen]...))
		m.cipherBuf = m.cipherBuf[packetLen:]
		m.plainBuf = m.plainBuf[packetLen:]
	}
	return parts
}

func (m *MsgSplitter) Flush() [][]byte {
	if m == nil || len(m.cipherBuf) == 0 {
		return nil
	}
	tail := append([]byte(nil), m.cipherBuf...)
	m.cipherBuf = nil
	m.plainBuf = nil
	return [][]byte{tail}
}

func (m *MsgSplitter) nextPacketLen() (int, bool) {
	if len(m.plainBuf) == 0 {
		return 0, false
	}
	switch m.proto {
	case protoAbridgedInt:
		first := m.plainBuf[0]
		headerLen := 1
		payloadLen := int(first&0x7f) * 4
		if first == 0x7f || first == 0xff {
			if len(m.plainBuf) < 4 {
				return 0, false
			}
			payloadLen = int(m.plainBuf[1]) | int(m.plainBuf[2])<<8 | int(m.plainBuf[3])<<16
			payloadLen *= 4
			headerLen = 4
		}
		if payloadLen <= 0 {
			return 0, true
		}
		packetLen := headerLen + payloadLen
		return packetLen, len(m.plainBuf) >= packetLen
	case protoIntermediateInt, protoPaddedIntermediateInt:
		if len(m.plainBuf) < 4 {
			return 0, false
		}
		payloadLen := int(binary.LittleEndian.Uint32(m.plainBuf[:4]) & 0x7fffffff)
		if payloadLen <= 0 {
			return 0, true
		}
		packetLen := 4 + payloadLen
		return packetLen, len(m.plainBuf) >= packetLen
	default:
		return 0, true
	}
}

type RawWebSocket struct {
	conn   net.Conn
	reader *bufio.Reader
	mu     sync.Mutex
	closed atomic.Bool
}

type WSHandshakeError struct {
	StatusCode int
	StatusLine string
	Location   string
}

func (e *WSHandshakeError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.StatusLine)
}

func (e *WSHandshakeError) IsRedirect() bool {
	return e.StatusCode == 301 || e.StatusCode == 302 || e.StatusCode == 303 || e.StatusCode == 307 || e.StatusCode == 308
}

func ConnectWS(ip, domain, path string, timeout time.Duration) (*RawWebSocket, error) {
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	raw, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(ip, "443"), &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return nil, err
	}
	_ = setTCPOptions(raw, 256*1024)
	keyRaw := make([]byte, 16)
	if _, err := rand.Read(keyRaw); err != nil {
		_ = raw.Close()
		return nil, err
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\nOrigin: https://web.telegram.org\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n\r\n",
		path, domain, base64.StdEncoding.EncodeToString(keyRaw))
	_ = raw.SetDeadline(time.Now().Add(timeout))
	if err := writeFull(raw, []byte(req)); err != nil {
		_ = raw.Close()
		return nil, err
	}
	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	if resp.StatusCode != http.StatusSwitchingProtocols {
		location := resp.Header.Get("Location")
		statusLine := resp.Proto + " " + resp.Status
		_ = raw.Close()
		return nil, &WSHandshakeError{StatusCode: resp.StatusCode, StatusLine: statusLine, Location: location}
	}
	return &RawWebSocket{conn: raw, reader: br}, nil
}

func (w *RawWebSocket) Send(data []byte) error {
	if w.closed.Load() {
		return net.ErrClosed
	}
	frame, err := buildWSFrame(0x2, data, true)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return writeFull(w.conn, frame)
}

func (w *RawWebSocket) Recv() ([]byte, error) {
	for !w.closed.Load() {
		opcode, payload, err := w.readFrame()
		if err != nil {
			return nil, err
		}
		switch opcode {
		case 0x8:
			w.closed.Store(true)
			_ = w.SendClose(payload)
			return nil, io.EOF
		case 0x9:
			_ = w.sendControl(0xA, payload)
		case 0xA:
			continue
		case 0x1, 0x2:
			return payload, nil
		}
	}
	return nil, io.EOF
}

func (w *RawWebSocket) SendClose(payload []byte) error {
	return w.sendControl(0x8, payload)
}

func (w *RawWebSocket) sendControl(opcode byte, payload []byte) error {
	frame, err := buildWSFrame(opcode, payload, true)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return writeFull(w.conn, frame)
}

func (w *RawWebSocket) Close() error {
	if w.closed.Swap(true) {
		return nil
	}
	_ = w.SendClose(nil)
	return w.conn.Close()
}

func (w *RawWebSocket) readFrame() (byte, []byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(w.reader, hdr); err != nil {
		return 0, nil, err
	}
	opcode := hdr[0] & 0x0f
	length := uint64(hdr[1] & 0x7f)
	if length == 126 {
		var ext [2]byte
		if _, err := io.ReadFull(w.reader, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	} else if length == 127 {
		var ext [8]byte
		if _, err := io.ReadFull(w.reader, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > math.MaxInt32 {
		return 0, nil, fmt.Errorf("websocket frame too large: %d", length)
	}
	var mask [4]byte
	masked := hdr[1]&0x80 != 0
	if masked {
		if _, err := io.ReadFull(w.reader, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(w.reader, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		xorMask(payload, mask[:])
	}
	return opcode, payload, nil
}

func buildWSFrame(opcode byte, data []byte, mask bool) ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte(0x80 | opcode)
	length := len(data)
	maskBit := byte(0)
	if mask {
		maskBit = 0x80
	}
	switch {
	case length < 126:
		b.WriteByte(maskBit | byte(length))
	case length <= 0xffff:
		b.WriteByte(maskBit | 126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(length))
		b.Write(ext[:])
	default:
		b.WriteByte(maskBit | 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(length))
		b.Write(ext[:])
	}
	if mask {
		var key [4]byte
		if _, err := rand.Read(key[:]); err != nil {
			return nil, err
		}
		masked := append([]byte(nil), data...)
		xorMask(masked, key[:])
		b.Write(key[:])
		b.Write(masked)
	} else {
		b.Write(data)
	}
	return b.Bytes(), nil
}

func xorMask(data []byte, mask []byte) {
	for i := range data {
		data[i] ^= mask[i%4]
	}
}

type WSPool struct {
	size int
	srv  *Server
	mu   sync.Mutex
	idle map[dcKey][]pooledWS
}

type pooledWS struct {
	ws      *RawWebSocket
	created time.Time
}

func NewWSPool(size int, srv *Server) *WSPool {
	return &WSPool{size: max(0, size), srv: srv, idle: make(map[dcKey][]pooledWS)}
}

func (p *WSPool) Get(ctx context.Context, key dcKey, targetIP string, domains []string) *RawWebSocket {
	p.mu.Lock()
	bucket := p.idle[key]
	now := time.Now()
	for len(bucket) > 0 {
		item := bucket[0]
		bucket = bucket[1:]
		if now.Sub(item.created) > 120*time.Second || item.ws.closed.Load() {
			go item.ws.Close()
			continue
		}
		p.idle[key] = bucket
		p.srv.stats.PoolHits.Add(1)
		go p.refill(context.Background(), key, targetIP, domains)
		p.mu.Unlock()
		return item.ws
	}
	p.idle[key] = bucket
	p.srv.stats.PoolMisses.Add(1)
	p.mu.Unlock()
	go p.refill(context.Background(), key, targetIP, domains)
	return nil
}

func (p *WSPool) Warmup(ctx context.Context, redirects map[int]string) {
	for dc, ip := range redirects {
		for _, isMedia := range []bool{false, true} {
			key := dcKey{DC: dc, IsMedia: isMedia}
			go p.refill(ctx, key, ip, wsDomains(dc, isMedia))
		}
	}
}

func (p *WSPool) refill(ctx context.Context, key dcKey, targetIP string, domains []string) {
	if p.size <= 0 {
		return
	}
	p.mu.Lock()
	needed := p.size - len(p.idle[key])
	p.mu.Unlock()
	for i := 0; i < needed; i++ {
		select {
		case <-ctx.Done():
			return
		default:
		}
		var ws *RawWebSocket
		for _, domain := range domains {
			c, err := ConnectWS(targetIP, domain, "/apiws", 8*time.Second)
			if err == nil {
				ws = c
				break
			}
			var hsErr *WSHandshakeError
			if errors.As(err, &hsErr) && hsErr.IsRedirect() {
				continue
			}
			break
		}
		if ws == nil {
			return
		}
		p.mu.Lock()
		if len(p.idle[key]) < p.size {
			p.idle[key] = append(p.idle[key], pooledWS{ws: ws, created: time.Now()})
			p.mu.Unlock()
		} else {
			p.mu.Unlock()
			_ = ws.Close()
		}
	}
}

func (s *Server) logStats(ctx context.Context) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			bl := s.blacklistSummary()
			totalPool := s.stats.PoolHits.Load() + s.stats.PoolMisses.Load()
			pool := "n/a"
			if totalPool > 0 {
				pool = fmt.Sprintf("%d/%d", s.stats.PoolHits.Load(), totalPool)
			}
			s.info.Printf("stats: total=%d active=%d ws=%d tcp_fb=%d cf=%d bad=%d err=%d pool=%s up=%s down=%s | ws_bl: %s",
				s.stats.ConnectionsTotal.Load(), s.stats.ConnectionsActive.Load(), s.stats.ConnectionsWS.Load(),
				s.stats.ConnectionsTCPFallback.Load(), s.stats.ConnectionsCFProxy.Load(), s.stats.ConnectionsBad.Load(),
				s.stats.WSErrors.Load(), pool, humanBytes(s.stats.BytesUp.Load()), humanBytes(s.stats.BytesDown.Load()), bl)
			s.writeStats()
		}
	}
}

func (s *Server) writeStats() {
	if s.cfg.StatsFile == "" {
		return
	}
	body, _ := json.MarshalIndent(map[string]int64{
		"connections_total":        s.stats.ConnectionsTotal.Load(),
		"connections_active":       s.stats.ConnectionsActive.Load(),
		"connections_ws":           s.stats.ConnectionsWS.Load(),
		"connections_tcp_fallback": s.stats.ConnectionsTCPFallback.Load(),
		"connections_cfproxy":      s.stats.ConnectionsCFProxy.Load(),
		"bytes_up":                 s.stats.BytesUp.Load(),
		"bytes_down":               s.stats.BytesDown.Load(),
	}, "", "  ")
	_ = os.WriteFile(s.cfg.StatsFile, body, 0644)
}

func (s *Server) isBlacklisted(key dcKey) bool {
	s.blacklistMu.Lock()
	defer s.blacklistMu.Unlock()
	return s.wsBlacklist[key]
}

func (s *Server) setBlacklisted(key dcKey) {
	s.blacklistMu.Lock()
	defer s.blacklistMu.Unlock()
	s.wsBlacklist[key] = true
}

func (s *Server) getFailUntil(key dcKey) (time.Time, bool) {
	s.blacklistMu.Lock()
	defer s.blacklistMu.Unlock()
	t, ok := s.failUntil[key]
	return t, ok
}

func (s *Server) setFailUntil(key dcKey, t time.Time) {
	s.blacklistMu.Lock()
	defer s.blacklistMu.Unlock()
	s.failUntil[key] = t
}

func (s *Server) clearFailUntil(key dcKey) {
	s.blacklistMu.Lock()
	defer s.blacklistMu.Unlock()
	delete(s.failUntil, key)
}

func (s *Server) blacklistSummary() string {
	s.blacklistMu.Lock()
	defer s.blacklistMu.Unlock()
	if len(s.wsBlacklist) == 0 {
		return "none"
	}
	var parts []string
	for key := range s.wsBlacklist {
		suffix := ""
		if key.IsMedia {
			suffix = "m"
		}
		parts = append(parts, fmt.Sprintf("DC%d%s", key.DC, suffix))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func wsDomains(dc int, isMedia bool) []string {
	if dc == 203 {
		dc = 2
	}
	if isMedia {
		return []string{fmt.Sprintf("kws%d-1.web.telegram.org", dc), fmt.Sprintf("kws%d.web.telegram.org", dc)}
	}
	return []string{fmt.Sprintf("kws%d.web.telegram.org", dc), fmt.Sprintf("kws%d-1.web.telegram.org", dc)}
}

var defaultDCIPs = map[int]string{
	1:   "149.154.175.50",
	2:   "149.154.167.51",
	3:   "149.154.175.100",
	4:   "149.154.167.91",
	5:   "149.154.171.5",
	203: "91.105.192.100",
}

func sortedDCs(m map[int]string) []int {
	out := make([]int, 0, len(m))
	for dc := range m {
		out = append(out, dc)
	}
	sort.Ints(out)
	return out
}

func linkHost(host string) string {
	if host != "0.0.0.0" {
		return host
	}
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", time.Second)
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return "127.0.0.1"
}

func humanBytes(n int64) string {
	v := float64(n)
	for _, unit := range []string{"B", "KB", "MB", "GB"} {
		if math.Abs(v) < 1024 {
			return fmt.Sprintf("%.1f%s", v, unit)
		}
		v /= 1024
	}
	return fmt.Sprintf("%.1fTB", v)
}

func setTCPOptions(conn net.Conn, bufferSize int) error {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}
	_ = tcp.SetNoDelay(true)
	_ = tcp.SetReadBuffer(bufferSize)
	_ = tcp.SetWriteBuffer(bufferSize)
	return nil
}

func ctxWithTimeout(d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	go func() {
		<-ctx.Done()
		cancel()
	}()
	return ctx
}
