package cfscanner

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	pkgscanner "github.com/lilendian0x00/xray-knife/v7/pkg/scanner"
	"github.com/lilendian0x00/xray-knife/v7/utils"
	"github.com/lilendian0x00/xray-knife/v7/utils/customlog"
	"github.com/spf13/cobra"
)

var (
	cliConfig pkgscanner.ScannerConfig
)

var CFscannerCmd = &cobra.Command{
	Use:   "cfscanner",
	Short: "Cloudflare's edge IP scanner with latency/speed tests and real-time resume.",
	Long: `Scans Cloudflare IP ranges to find optimal edge nodes. It supports latency testing,
speed testing, and can resume scans from previous results. The results are saved
in a CSV file for easy analysis and reuse. You can provide subnets, single IPs,
or pass a file containing IPs/CIDRs (one per line).`,
	Run: func(cmd *cobra.Command, args []string) {

		var allSubnets []string

		for _, arg := range cliConfig.Subnets {
			// اگر فایل بود
			if fileInfo, err := os.Stat(arg); err == nil && !fileInfo.IsDir() {
				lines := utils.ParseFileByNewline(arg)
				for _, line := range lines {
					if normalized, err := normalizeIPOrCIDR(strings.TrimSpace(line)); err == nil {
						allSubnets = append(allSubnets, normalized)
					} else {
						customlog.Printf(customlog.Warning, "Invalid IP/CIDR skipped: %s\n", line)
					}
				}
			} else {
				if normalized, err := normalizeIPOrCIDR(strings.TrimSpace(arg)); err == nil {
					allSubnets = append(allSubnets, normalized)
				} else {
					customlog.Printf(customlog.Warning, "Invalid IP/CIDR skipped: %s\n", arg)
				}
			}
		}

		if len(allSubnets) == 0 {
			customlog.Printf(customlog.Failure, "No valid IPs or subnets found. Please provide valid input.\n")
			return
		}

		cliConfig.Subnets = allSubnets

		if !cliConfig.Resume {
			if err := os.Remove(cliConfig.OutputFile); err != nil && !os.IsNotExist(err) {
				customlog.Printf(customlog.Failure, "Failed to clear previous results file %s: %v\n", cliConfig.OutputFile, err)
				return
			}
		}

		service, err := pkgscanner.NewScannerService(cliConfig, log.New(os.Stdout, "", 0))
		if err != nil {
			customlog.Printf(customlog.Failure, "Failed to create scanner: %v\n", err)
			return
		}

		progressChan := make(chan *pkgscanner.ScanResult, cliConfig.ThreadCount)

		finalResultsMap := make(map[string]*pkgscanner.ScanResult)
		var mapMu sync.Mutex
		var wg sync.WaitGroup
		wg.Add(1)

		go func() {
			defer wg.Done()
			for res := range progressChan {
				mapMu.Lock()
				finalResultsMap[res.IP] = res
				mapMu.Unlock()

				if res.Error != nil {
					if cliConfig.Verbose {
						customlog.Printf(customlog.Warning, "IP %s failed test: %v\n", res.IP, res.Error)
					}
				} else if res.DownSpeed > 0 || res.UpSpeed > 0 {
					customlog.Printf(customlog.Success,
						"SPEEDTEST: %-20s | %-10v | %-15.2f | %-15.2f\n",
						res.IP,
						res.Latency.Round(time.Millisecond),
						res.DownSpeed,
						res.UpSpeed,
					)
				} else {
					customlog.Printf(customlog.Success,
						"LATENCY:   %-20s | %-10v\n",
						res.IP,
						res.Latency.Round(time.Millisecond),
					)
				}
			}
		}()

		if err := service.Run(context.Background(), progressChan); err != nil {
			customlog.Printf(customlog.Failure, "Scan encountered an error: %v\n", err)
		}

		wg.Wait()

		mapMu.Lock()
		var finalResults []*pkgscanner.ScanResult
		for _, result := range finalResultsMap {
			finalResults = append(finalResults, result)
		}
		mapMu.Unlock()

		printResultsToConsole(finalResults, cliConfig.DoSpeedtest, cliConfig.OnlySpeedtestResults)
		customlog.Printf(customlog.Success, "Scan finished. Final results saved to %s\n", cliConfig.OutputFile)
	},
}

func init() {
	CFscannerCmd.Flags().StringSliceVarP(&cliConfig.Subnets, "subnets", "s", nil, "IP(s), subnet(s), or file containing IP/CIDR (one per line)")
	CFscannerCmd.Flags().IntVarP(&cliConfig.ThreadCount, "threads", "t", 100, "Count of threads for latency scan")
	CFscannerCmd.Flags().BoolVarP(&cliConfig.DoSpeedtest, "speedtest", "p", false, "Measure download/upload speed on the fastest IPs")
	CFscannerCmd.Flags().IntVarP(&cliConfig.SpeedtestTop, "speedtest-top", "c", 10, "Number of fastest IPs to select for speed testing")
	CFscannerCmd.Flags().IntVar(&cliConfig.SpeedtestConcurrency, "speedtest-concurrency", 4, "Number of concurrent speed tests to run")
	CFscannerCmd.Flags().IntVar(&cliConfig.SpeedtestTimeout, "speedtest-timeout", 30, "Total timeout in seconds for one IP's speed test")
	CFscannerCmd.Flags().IntVarP(&cliConfig.RequestTimeout, "timeout", "u", 5000, "Individual request timeout (in ms)")
	CFscannerCmd.Flags().BoolVarP(&cliConfig.ShowTraceBody, "body", "b", false, "Show trace body output")
	CFscannerCmd.Flags().BoolVarP(&cliConfig.Verbose, "verbose", "v", false, "Show verbose output with detailed errors")
	CFscannerCmd.Flags().BoolVarP(&cliConfig.ShuffleSubnets, "shuffle-subnet", "e", false, "Shuffle list of Subnets")
	CFscannerCmd.Flags().BoolVarP(&cliConfig.ShuffleIPs, "shuffle-ip", "i", false, "Shuffle list of IPs")
	CFscannerCmd.Flags().StringVarP(&cliConfig.OutputFile, "output", "o", "results.csv", "Output file to save sorted results (in CSV format)")
	CFscannerCmd.Flags().IntVarP(&cliConfig.RetryCount, "retry", "r", 1, "Number of times to retry TCP connection on failure")
	CFscannerCmd.Flags().BoolVarP(&cliConfig.OnlySpeedtestResults, "only-speedtest", "k", false, "Only display results that have successful speedtest data")
	CFscannerCmd.Flags().IntVarP(&cliConfig.DownloadMB, "download-mb", "d", 20, "Custom amount of data to download for speedtest (in MB)")
	CFscannerCmd.Flags().IntVarP(&cliConfig.UploadMB, "upload-mb", "m", 10, "Custom amount of data to upload for speedtest (in MB)")
	CFscannerCmd.Flags().StringVarP(&cliConfig.ConfigLink, "config", "C", "", "Use a config link as a proxy to test IPs")
	CFscannerCmd.Flags().BoolVarP(&cliConfig.InsecureTLS, "insecure", "E", false, "Allow insecure TLS connections for the proxy config")
	CFscannerCmd.Flags().BoolVar(&cliConfig.Resume, "resume", false, "Resume scan from previous results (file or DB)")
	CFscannerCmd.Flags().BoolVar(&cliConfig.SaveToDB, "save-db", false, "Save scan results to the database")

	_ = CFscannerCmd.MarkFlagRequired("subnets")
}

// ---------- helpers ----------

func normalizeIPOrCIDR(input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("empty input")
	}

	// CIDR
	if _, _, err := net.ParseCIDR(input); err == nil {
		return input, nil
	}

	// Single IP
	if ip := net.ParseIP(input); ip != nil {
		if ip.To4() != nil {
			return ip.String() + "/32", nil
		}
		return ip.String() + "/128", nil
	}

	return "", fmt.Errorf("invalid IP or CIDR")
}

func printResultsToConsole(results []*pkgscanner.ScanResult, doSpeedtest, onlySpeedtestResults bool) {
	var successfulResults, finalResults []*pkgscanner.ScanResult

	for _, r := range results {
		if r.Error == nil {
			successfulResults = append(successfulResults, r)
		}
	}

	if len(successfulResults) == 0 {
		customlog.Printf(customlog.Warning, "No successful IPs found to display.\n")
		return
	}

	if doSpeedtest && onlySpeedtestResults {
		for _, r := range successfulResults {
			if r.DownSpeed > 0 || r.UpSpeed > 0 {
				finalResults = append(finalResults, r)
			}
		}
	} else {
		finalResults = successfulResults
	}

	if len(finalResults) == 0 {
		customlog.Printf(customlog.Warning, "No results to display after filtering.\n")
		return
	}

	sort.Slice(finalResults, func(i, j int) bool {
		if doSpeedtest {
			if finalResults[i].Latency != finalResults[j].Latency {
				return finalResults[i].Latency < finalResults[j].Latency
			}
			return finalResults[i].DownSpeed > finalResults[j].DownSpeed
		}
		return finalResults[i].Latency < finalResults[j].Latency
	})

	var header string
	var outputLines []string

	if doSpeedtest {
		header = fmt.Sprintf("%-20s | %-10s | %-15s | %-15s", "IP", "Latency", "Downlink (Mbps)", "Uplink (Mbps)")
	} else {
		header = fmt.Sprintf("%-20s | %-10s", "IP", "Latency")
	}

	outputLines = append(outputLines, header)

	for _, result := range finalResults {
		outputLines = append(outputLines, formatResultLine(*result, doSpeedtest))
	}

	customlog.Println(customlog.GetColor(customlog.None, "\n--- Sorted Results ---\n"))
	customlog.Println(customlog.GetColor(customlog.Success, strings.Join(outputLines, "\n")))
	customlog.Println(customlog.GetColor(customlog.None, "\n--------------------\n"))
}

func formatResultLine(result pkgscanner.ScanResult, speedtestEnabled bool) string {
	if speedtestEnabled {
		return fmt.Sprintf(
			"%-20s | %-10v | %-15.2f | %-15.2f",
			result.IP,
			result.Latency.Round(time.Millisecond),
			result.DownSpeed,
			result.UpSpeed,
		)
	}
	return fmt.Sprintf("%-20s | %-10v", result.IP, result.Latency.Round(time.Millisecond))
}
