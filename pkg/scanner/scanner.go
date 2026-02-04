package scanner

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/alitto/pond/v2"
	"github.com/gocarina/gocsv"
	"github.com/lilendian0x00/xray-knife/v7/utils"
)

// zeroReader endlessly produces zero bytes
type zeroReader struct{}

func (z zeroReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// ScannerConfig holds scan configuration
type ScannerConfig struct {
	Subnets        []string `json:"subnets"`
	ThreadCount    int      `json:"threadCount"`
	ShuffleIPs     bool     `json:"shuffleIPs"`
	ShuffleSubnets bool     `json:"shuffleSubnets"`
	RequestTimeout int      `json:"timeout"`
	Verbose        bool     `json:"verbose"`
	OutputFile     string   `json:"outputFile"`
	RetryCount     int      `json:"retry"`
}

// ScannerService main scanner
type ScannerService struct {
	config     ScannerConfig
	logger     *log.Logger
	scannedIPs map[string]bool
}

// ScanResult stores single IP scan result
type ScanResult struct {
	IP        string        `csv:"ip" json:"ip"`
	Latency   time.Duration `csv:"-" json:"-"`
	LatencyMS int64         `csv:"latency_ms" json:"latency_ms"`
	Error     error         `csv:"-" json:"-"`
	ErrorStr  string        `csv:"error,omitempty" json:"error,omitempty"`
	mu        sync.Mutex    `csv:"-" json:"-"`
}

// PrepareForMarshal fills marshal-friendly fields
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

// NewScannerService creates scanner
func NewScannerService(config ScannerConfig, logger *log.Logger) *ScannerService {
	return &ScannerService{
		config:     config,
		logger:     logger,
		scannedIPs: make(map[string]bool),
	}
}

// Run executes the scan
func (s *ScannerService) Run(ctx context.Context, progressChan chan<- *ScanResult) error {
	defer close(progressChan)

	workerResultsChan := make(chan *ScanResult, s.config.ThreadCount*2)
	var mapMu sync.Mutex
	runResultsMap := make(map[string]*ScanResult)
	var writerWg sync.WaitGroup
	writerWg.Add(1)

	// Writer goroutine
	go func() {
		defer writerWg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case result, ok := <-workerResultsChan:
				if !ok {
					return
				}
				mapMu.Lock()
				runResultsMap[result.IP] = result
				mapMu.Unlock()
				select {
				case progressChan <- result:
				case <-ctx.Done():
				default:
				}
			}
		}
	}()

	// Run Latency Scan
	if err := s.runLatencyScan(ctx, workerResultsChan); err != nil {
		if !errors.Is(err, context.Canceled) {
			s.logger.Printf("Latency scan failed: %v", err)
		}
		s.logger.Println("Latency scan cancelled.")
	} else {
		s.logger.Println("Latency scan phase finished.")
	}

	close(workerResultsChan)
	writerWg.Wait()

	// Save final results
	finalResultsSlice := make([]*ScanResult, 0, len(runResultsMap))
	for _, r := range runResultsMap {
		r.PrepareForMarshal()
		finalResultsSlice = append(finalResultsSlice, r)
	}

	sort.Slice(finalResultsSlice, func(i, j int) bool {
		return finalResultsSlice[i].Latency < finalResultsSlice[j].Latency
	})

	if err := saveResultsToCSV(s.config.OutputFile, finalResultsSlice); err != nil {
		s.logger.Printf("Error saving CSV: %v", err)
		return err
	}

	s.logger.Println("Scan completed.")
	return nil
}

// runLatencyScan scans each IP for latency
func (s *ScannerService) runLatencyScan(ctx context.Context, workerResultsChan chan<- *ScanResult) error {
	pool := pond.NewPool(s.config.ThreadCount)
	defer pool.Stop()
	group := pool.NewGroupContext(ctx)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	subnets := s.config.Subnets
	if s.config.ShuffleSubnets {
		r.Shuffle(len(subnets), func(i, j int) { subnets[i], subnets[j] = subnets[j], subnets[i] })
	}

	for _, cidr := range subnets {
		listIP, err := utils.CIDRtoListIP(cidr)
		if err != nil {
			s.logger.Printf("Invalid CIDR %s: %v", cidr, err)
			continue
		}

		if s.config.ShuffleIPs {
			r.Shuffle(len(listIP), func(i, j int) { listIP[i], listIP[j] = listIP[j], listIP[i] })
		}

		for _, ip := range listIP {
			if _, ok := s.scannedIPs[ip]; ok {
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

	return group.Wait()
}

// scanIPForLatency performs simple latency measurement
func (s *ScannerService) scanIPForLatency(ctx context.Context, ip string) *ScanResult {
	result := &ScanResult{IP: ip}
	client := &http.Client{Timeout: time.Duration(s.config.RequestTimeout) * time.Millisecond}
	url := fmt.Sprintf("https://%s", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		result.Error = fmt.Errorf("request failed: %w", err)
		return result
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Errorf("latency failed: %w", err)
		return result
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	result.Latency = time.Since(start)
	return result
}

// saveResultsToCSV writes results to CSV
func saveResultsToCSV(filePath string, results []*ScanResult) error {
	if len(results) == 0 {
		return nil
	}
	for _, r := range results {
		r.PrepareForMarshal()
	}
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("cannot create file: %w", err)
	}
	defer file.Close()
	return gocsv.MarshalFile(&results, file)
}
