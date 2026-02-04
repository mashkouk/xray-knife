package scanner

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/alitto/pond/v2"
	"github.com/gocarina/gocsv"
	"github.com/lilendian0x00/xray-knife/v7/database"
	"github.com/lilendian0x00/xray-knife/v7/pkg/core"
	"github.com/lilendian0x00/xray-knife/v7/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v7/utils"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

/* -------------------- helpers -------------------- */

type zeroReader struct{}

func (z zeroReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

/* -------------------- config & structs -------------------- */

type ScannerConfig struct {
	Subnets              []string `json:"subnets"`
	ThreadCount          int      `json:"threadCount"`
	ShuffleIPs           bool     `json:"shuffleIPs"`
	ShuffleSubnets       bool     `json:"shuffleSubnets"`
	DoSpeedtest          bool     `json:"doSpeedtest"`
	RequestTimeout       int      `json:"timeout"`
	ShowTraceBody        bool     `json:"showTraceBody"`
	Verbose              bool     `json:"verbose"`
	OutputFile           string   `json:"outputFile"`
	RetryCount           int      `json:"retry"`
	OnlySpeedtestResults bool     `json:"onlySpeedtestResults"`
	DownloadMB           int      `json:"downloadMB"`
	UploadMB             int      `json:"uploadMB"`
	SpeedtestTop         int      `json:"speedtestTop"`
	SpeedtestConcurrency int      `json:"speedtestConcurrency"`
	SpeedtestTimeout     int      `json:"speedtestTimeout"`
	ConfigLink           string   `json:"configLink"`
	InsecureTLS          bool     `json:"insecureTLS"`
	Resume               bool     `json:"resume"`
	SaveToDB             bool     `json:"saveToDB"`
}

type ScannerService struct {
	config          ScannerConfig
	logger          *log.Logger
	xrayCore        core.Core
	singboxCore     core.Core
	selectedCoreMap map[string]core.Core
	initialResults  []*ScanResult
	scannedIPs      map[string]bool
}

type ScanResult struct {
	IP        string        `csv:"ip" json:"ip"`
	Latency   time.Duration `csv:"-" json:"-"`
	LatencyMS int64         `csv:"latency_ms" json:"latency_ms"`
	DownSpeed float64       `csv:"download_mbps" json:"download_mbps"`
	UpSpeed   float64       `csv:"upload_mbps" json:"upload_mbps"`
	Error     error         `csv:"-" json:"-"`
	ErrorStr  string        `csv:"error,omitempty" json:"error,omitempty"`
	mu        sync.Mutex    `csv:"-" json:"-"`
}

func (r *ScanResult) PrepareForMarshal() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.LatencyMS = r.Latency.Milliseconds()
	if r.Error != nil {
		r.ErrorStr = r.Error.Error()
	} else {
		r.ErrorStr = ""
	}
}

/* -------------------- constructor -------------------- */

func NewScannerService(config ScannerConfig, logger *log.Logger) (*ScannerService, error) {
	s := &ScannerService{
		config:     config,
		logger:     logger,
		scannedIPs: make(map[string]bool),
	}

	if s.config.ConfigLink != "" {
		s.xrayCore = core.CoreFactory(core.XrayCoreType, s.config.InsecureTLS, s.config.Verbose)
		s.singboxCore = core.CoreFactory(core.SingboxCoreType, s.config.InsecureTLS, s.config.Verbose)
		s.selectedCoreMap = map[string]core.Core{
			protocol.VmessIdentifier:        s.xrayCore,
			protocol.VlessIdentifier:        s.xrayCore,
			protocol.ShadowsocksIdentifier:  s.xrayCore,
			protocol.TrojanIdentifier:       s.xrayCore,
			protocol.SocksIdentifier:        s.xrayCore,
			protocol.WireguardIdentifier:    s.xrayCore,
			protocol.Hysteria2Identifier:    s.singboxCore,
			"hy2":                           s.singboxCore,
		}
	}

	return s, nil
}

/* -------------------- public API -------------------- */

func (s *ScannerService) Run(ctx context.Context, progressChan chan<- *ScanResult) error {
	defer close(progressChan)

	workerResultsChan := make(chan *ScanResult, s.config.ThreadCount*2)
	pool := pond.NewPool(s.config.ThreadCount)
	defer pool.Stop()

	group := pool.NewGroupContext(ctx)

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	if s.config.ShuffleSubnets {
		r.Shuffle(len(s.config.Subnets), func(i, j int) {
			s.config.Subnets[i], s.config.Subnets[j] = s.config.Subnets[j], s.config.Subnets[i]
		})
	}

	var hasIPs bool

	for _, input := range s.config.Subnets {
		ips, err := utils.CIDRtoListIP(input)
		if err != nil {
			s.logger.Printf("Invalid IP/CIDR %s: %v", input, err)
			continue
		}

		if len(ips) == 0 {
			continue
		}
		hasIPs = true

		if s.config.ShuffleIPs {
			r.Shuffle(len(ips), func(i, j int) {
				ips[i], ips[j] = ips[j], ips[i]
			})
		}

		for _, ip := range ips {
			if s.scannedIPs[ip] {
				continue
			}

			ipToScan := ip
			group.Submit(func() {
				res := s.scanIPForLatency(group.Context(), ipToScan)
				select {
				case workerResultsChan <- res:
				case <-group.Context().Done():
				}
			})
		}
	}

	if !hasIPs {
		return errors.New("no valid IPs to scan")
	}

	go func() {
		group.Wait()
		close(workerResultsChan)
	}()

	results := make(map[string]*ScanResult)

	for res := range workerResultsChan {
		results[res.IP] = res
		progressChan <- res
	}

	var final []*ScanResult
	for _, r := range results {
		r.PrepareForMarshal()
		final = append(final, r)
	}

	sort.Slice(final, func(i, j int) bool {
		return final[i].Latency < final[j].Latency
	})

	return saveResultsToCSV(s.config.OutputFile, final)
}

/* -------------------- scanning logic -------------------- */

func (s *ScannerService) scanIPForLatency(ctx context.Context, ip string) *ScanResult {
	result := &ScanResult{IP: ip}

	req, err := http.NewRequestWithContext(ctx, "GET", cloudflareTraceURL, nil)
	if err != nil {
		result.Error = err
		return result
	}

	req.Header.Set("User-Agent", "Mozilla/5.0")

	transport := NewBypassJA3Transport(utls.HelloChrome_Auto)
	transport.DialContext = s.createDialerWithRetry(ip, s.config.RetryCount)

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(s.config.RequestTimeout) * time.Millisecond,
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	io.ReadAll(resp.Body)
	result.Latency = time.Since(start)

	return result
}

/* -------------------- networking helpers -------------------- */

func (s *ScannerService) createDialerWithRetry(ip string, retries int) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := &net.Dialer{Timeout: time.Duration(s.config.RequestTimeout) * time.Millisecond}
		target := fmt.Sprintf("%s:443", ip)

		var lastErr error
		for i := 0; i <= retries; i++ {
			conn, err := d.DialContext(ctx, network, target)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

/* -------------------- CSV -------------------- */

func saveResultsToCSV(filePath string, results []*ScanResult) error {
	if len(results) == 0 {
		return nil
	}
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	return gocsv.MarshalFile(&results, file)
}

/* -------------------- constants -------------------- */

const (
	cloudflareTraceURL = "https://cloudflare.com/cdn-cgi/trace"
)
