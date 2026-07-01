package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"html"
	"html/template"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
)

// ============================================================================
// Core Data Structures
// ============================================================================

type Config struct {
	Target       string
	TargetsFile  string
	RequestFile  string
	Wordlists    []string
	Workers      int
	Timeout      int
	Delay        float64
	Jitter       float64
	Proxy        string
	OutputDir    string
	OutputFormat string
	Quiet        bool
	Verbose      bool

	FilterMode    string
	FilterStatus  []int
	FilterSize    []int
	FilterWords   []int
	FilterLines   []int
	FilterRegex   string
	FilterTime    int64
	FilterAutoCal bool

	MatchStatus []int
	MatchSize   []int
	MatchWords  []int
	MatchLines  []int
	MatchRegex  string
	MatchTime   int64

	Recursion       bool
	RecursionDepth  int
	RecursionStatus []int
	Methods         []string
	Extensions      []string
	StopOnSuccess   bool
	StopOnErrors    int
	MaxTime         int

	RandomAgent   bool
	Encoding      string
	RateLimit     int
	RetryCount    int
	RetryDelay    int

	SaveResponses bool
	PreviewLength int
	HideProgress  bool

	// Advanced features
	EvasionLevel     int
	CalibrateRounds  int
	AnomalyThreshold float64
	Soft404Detect    bool
	FollowRedirects  bool
	HTTP2            bool
	DiffEngine       bool
}

type StatisticalBaseline struct {
	SizeStats    *ResponseStats
	WordStats    *ResponseStats
	LineStats    *ResponseStats
	LatencyStats *ResponseStats
	HashFreq     map[string]int
	Profiles     []ResponseProfile
	SampleBodies []string
}

type ResponseStats struct {
	Mean   float64
	Median float64
	StdDev float64
	Q1     float64
	Q3     float64
	IQR    float64
	Values []float64
}

type ResponseProfile struct {
	StatusCode  int
	Size        int
	Words       int
	Lines       int
	LatencyMs   int64
	ContentHash string
}

type Finding struct {
	ID              int      `json:"id"`
	Timestamp       string   `json:"timestamp"`
	URL             string   `json:"url"`
	Method          string   `json:"method"`
	Payload         string   `json:"payload"`
	StatusCode      int      `json:"status_code"`
	ResponseSize    int      `json:"response_size"`
	Words           int      `json:"words"`
	Lines           int      `json:"lines"`
	SizeDeltaPct    float64  `json:"size_delta_pct"`
	WordDeltaPct    float64  `json:"word_delta_pct"`
	LineDeltaPct    float64  `json:"line_delta_pct"`
	LatencyMs       int64    `json:"latency_ms"`
	LatencyDeltaMs  int64    `json:"latency_delta_ms"`
	ContentHash     string   `json:"content_hash"`
	IsAnomaly       bool     `json:"is_anomaly"`
	AnomalyScore    float64  `json:"anomaly_score"`
	AnomalyReasons  []string `json:"anomaly_reasons"`
	RawRequest      string   `json:"raw_request"`
	ResponsePreview string   `json:"response_preview,omitempty"`
	RawResponse     string   `json:"-"`
	RedirectURL     string   `json:"redirect_url,omitempty"`
	MatchFilters    []string `json:"match_filters"`
}

type Report struct {
	Session struct {
		Target    string   `json:"target"`
		Targets   []string `json:"targets"`
		StartTime string   `json:"start_time"`
		EndTime   string   `json:"end_time"`
		Duration  string   `json:"duration"`
		TotalReqs int64    `json:"total_requests"`
		TotalHits int64    `json:"total_hits"`
		Workers   int      `json:"workers"`
		Wordlists []string `json:"wordlists"`
		RPS       float64  `json:"requests_per_second"`
	} `json:"session"`
	Baseline struct {
		AvgSize      int               `json:"avg_size"`
		AvgWords     int               `json:"avg_words"`
		AvgLines     int               `json:"avg_lines"`
		AvgLatencyMs int64             `json:"avg_latency_ms"`
		Responses    []ResponseProfile `json:"responses"`
	} `json:"baseline"`
	Hits       []Finding  `json:"hits"`
	Statistics Statistics `json:"statistics"`
	Config     Config     `json:"configuration"`
}

type Statistics struct {
	ByStatusCode    map[string]int `json:"by_status_code"`
	BySize          map[string]int `json:"by_size"`
	ByAnomalyReason map[string]int `json:"by_anomaly_reason"`
	ByResponseTime  map[string]int `json:"by_response_time"`
	Errors          map[string]int `json:"errors"`
}

type Task struct {
	Target  string
	Payload []string
	Index   int
}

// ============================================================================
// Global Variables
// ============================================================================

var (
	uaList = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
	}

	errorSigs = []string{
		`(?i)sql syntax.*mysql`,
		`(?i)warning.*mysql_.*`,
		`(?i)valid mysql result`,
		`(?i)postgresql.*error`,
		`(?i)warning.*pg_.*`,
		`(?i)ora-[0-9]+`,
		`(?i)pls-[0-9]+`,
		`(?i)microsoft sql.*error`,
		`(?i)odbc sql server driver`,
		`(?i)sqlite/jdbcdriver`,
		`(?i)sqliteexception`,
		`(?i)system\.data\.sqlite`,
		`(?i)root:x:0:0`,
		`(?i)[a-z]+:x:[0-9]+:[0-9]+:.*:.*:`,
		`(?i)gid=.*groups=`,
		`(?i)traceback \(most recent call last\)`,
		`(?i)file "/.*", line `,
		`(?i)javax\.servlet\.\S+exception`,
		`(?i)java\.lang\.\S+exception`,
		`(?i)ruby on rails`,
		`(?i)django`,
		`(?i)laravel\.log`,
		`(?i)fatal error`,
		`(?i)parse error`,
		`(?i)undefined (index|variable)`,
		`(?i)warning: (include|require|fopen|file_get_contents)`,
		`(?i)failed to open stream`,
		`(?i)no such file or directory`,
		`(?i)exception in thread`,
		`(?i)nested exception is`,
		`(?i)cannot modify header information`,
		`(?i)headers already sent`,
		`(?i)php warning`,
		`(?i)php error`,
	}

	colors = struct {
		Info    *color.Color
		Success *color.Color
		Warning *color.Color
		Error   *color.Color
		Muted   *color.Color
	}{
		Info:    color.New(color.FgCyan),
		Success: color.New(color.FgGreen, color.Bold),
		Warning: color.New(color.FgYellow),
		Error:   color.New(color.FgRed, color.Bold),
		Muted:   color.New(color.FgHiBlack),
	}
)

// ============================================================================
// Soft 404 Detector
// ============================================================================

type Soft404Detector struct {
	mu      sync.RWMutex
	samples map[string][]string
	hashes  map[string]int
}

func NewSoft404Detector() *Soft404Detector {
	return &Soft404Detector{
		samples: make(map[string][]string),
		hashes:  make(map[string]int),
	}
}

func (s *Soft404Detector) normalizePath(pathStr string) string {
	u, err := url.Parse(pathStr)
	if err != nil {
		return "/"
	}
	dir := path.Dir(u.Path)
	if dir == "." || dir == "" {
		return "/"
	}
	return dir
}

func (s *Soft404Detector) Add(pathStr, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.normalizePath(pathStr)
	if len(s.samples[key]) < 5 {
		s.samples[key] = append(s.samples[key], body)
	}
	s.hashes[fnvHash(body)]++
}

func (s *Soft404Detector) IsSoft404(pathStr, body string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := s.normalizePath(pathStr)
	samples, ok := s.samples[key]
	if !ok || len(samples) == 0 {
		parent := s.normalizePath(key)
		if parent == key {
			return false
		}
		samples, ok = s.samples[parent]
		if !ok || len(samples) == 0 {
			return false
		}
	}

	h := fnvHash(body)
	if s.hashes[h] >= 2 {
		return true
	}

	maxSim := 0.0
	for _, sample := range samples {
		sim := jaccardSimilarity(body, sample)
		if sim > maxSim {
			maxSim = sim
		}
	}
	return maxSim > 0.88
}

// ============================================================================
// Main Function
// ============================================================================

func main() {
	cfg := parseFlags()

	if cfg.RequestFile == "" || len(cfg.Wordlists) == 0 {
		printUsage()
		os.Exit(1)
	}

	os.MkdirAll(cfg.OutputDir, 0755)
	os.MkdirAll(filepath.Join(cfg.OutputDir, "responses"), 0755)
	os.MkdirAll(filepath.Join(cfg.OutputDir, "replay"), 0755)

	targets := resolveTargets(cfg)
	if len(targets) == 0 {
		colors.Error.Println("[!] No valid targets found")
		os.Exit(1)
	}

	wordlists := loadWordlists(cfg.Wordlists)
	if len(wordlists) == 0 {
		colors.Error.Println("[!] Failed to load wordlists")
		os.Exit(1)
	}

	rawTemplate, err := os.ReadFile(cfg.RequestFile)
	if err != nil {
		colors.Error.Printf("[!] Cannot read request file: %v\n", err)
		os.Exit(1)
	}
	template := string(rawTemplate)

	client := buildClient(cfg)

	payloads := generatePayloads(wordlists, cfg.Extensions)
	colors.Info.Printf("[+] Generated %d payload combinations\n", len(payloads))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		colors.Error.Println("\n[!] Interrupted, shutting down...")
		cancel()
	}()

	colors.Info.Println("[+] Calibrating statistical baseline...")
	baseline := calibrateStatistical(client, cfg, template, targets[0])
	colors.Success.Printf("[+] Baseline: %.0f bytes (\u03c3=%.1f) | %.0f words | %.0f lines | %.0fms (\u03c3=%.1f)\n",
		baseline.SizeStats.Mean, baseline.SizeStats.StdDev,
		baseline.WordStats.Mean, baseline.LineStats.Mean,
		baseline.LatencyStats.Median, baseline.LatencyStats.StdDev)

	if cfg.FilterAutoCal {
		autoCalibrateFilters(cfg, baseline)
	}

	var soft404 *Soft404Detector
	if cfg.Soft404Detect {
		soft404 = NewSoft404Detector()
		colors.Info.Println("[+] Soft-404 detection enabled")
	}

	start := time.Now()
	findings, totalReqs := runScan(ctx, cfg, client, baseline, soft404, template, targets, payloads)

	// Recursion
	if cfg.Recursion && cfg.RecursionDepth > 0 {
		allFindings := findings
		currentTargets := make([]string, len(targets))
		copy(currentTargets, targets)

		for depth := 1; depth <= cfg.RecursionDepth; depth++ {
			seeds := extractRecursionSeeds(allFindings, cfg)
			if len(seeds) == 0 {
				break
			}

			var newTargets []string
			seen := make(map[string]bool)
			for _, t := range currentTargets {
				seen[t] = true
			}
			for _, s := range seeds {
				if !seen[s] {
					seen[s] = true
					newTargets = append(newTargets, s)
				}
			}
			if len(newTargets) == 0 {
				break
			}

			colors.Info.Printf("[+] Recursion depth %d: %d new directories\n", depth, len(newTargets))
			currentTargets = append(currentTargets, newTargets...)

			depthFindings, depthReqs := runScan(ctx, cfg, client, baseline, soft404, template, newTargets, payloads)
			totalReqs += depthReqs
			allFindings = append(allFindings, depthFindings...)
		}
		findings = allFindings
	}

	duration := time.Since(start)

	report := buildReport(cfg, baseline, findings, duration, totalReqs, targets)

	outputFormats := []string{cfg.OutputFormat}
	if cfg.OutputFormat == "all" {
		outputFormats = []string{"json", "csv", "html", "md"}
	}

	for _, format := range outputFormats {
		saveReport(report, cfg.OutputDir, format)
	}

	if !cfg.Quiet {
		printSummary(report)
		writeReplayFiles(findings, cfg.OutputDir)
		writeCurlScripts(findings, cfg.OutputDir)
	}

	colors.Success.Printf("\n[+] Scan complete: %d requests | %d hits | Duration: %s\n",
		report.Session.TotalReqs, report.Session.TotalHits, duration)
}

// ============================================================================
// Scan Engine
// ============================================================================

func runScan(ctx context.Context, cfg *Config, client *http.Client, baseline *StatisticalBaseline, soft404 *Soft404Detector, template string, targets []string, payloads [][]string) ([]Finding, int64) {
	var (
		completed int64
		hits      int64
		errors    int64
		start     = time.Now()
	)

	totalTasks := int64(len(payloads) * len(targets))
	taskCh := make(chan Task, totalTasks)

	for _, target := range targets {
		for i, payload := range payloads {
			select {
			case <-ctx.Done():
				close(taskCh)
				return nil, 0
			default:
				taskCh <- Task{Target: target, Payload: payload, Index: i}
			}
		}
	}
	close(taskCh)

	var bar *progressbar.ProgressBar
	if !cfg.HideProgress && !cfg.Quiet {
		bar = progressbar.NewOptions64(
			totalTasks,
			progressbar.OptionSetDescription("Scanning..."),
			progressbar.OptionShowCount(),
			progressbar.OptionShowIts(),
			progressbar.OptionSetItsString("req/s"),
			progressbar.OptionThrottle(100*time.Millisecond),
			progressbar.OptionSetRenderBlankState(true),
		)
	}

	var findings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	rateLimiter := NewRateLimiter(cfg.RateLimit)

	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for task := range taskCh {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if cfg.MaxTime > 0 && time.Since(start).Seconds() > float64(cfg.MaxTime) {
					return
				}

				if cfg.RateLimit > 0 {
					rateLimiter.Wait()
				}

				f := executeTask(ctx, client, cfg, baseline, soft404, template, task, workerID)

				if shouldSkip(f, cfg) {
					atomic.AddInt64(&completed, 1)
					if bar != nil {
						bar.Add(1)
					}
					continue
				}

				if f.IsAnomaly || len(f.MatchFilters) > 0 {
					atomic.AddInt64(&hits, 1)

					mu.Lock()
					findings = append(findings, f)
					mu.Unlock()

					if !cfg.Quiet {
						printFinding(f, cfg)
					}

					if cfg.SaveResponses {
						saveResponse(f, cfg.OutputDir)
					}

					if cfg.StopOnSuccess {
						return
					}
				}

				if len(f.AnomalyReasons) > 0 && containsStr(f.AnomalyReasons, "CONNECTION_ERROR") {
					atomic.AddInt64(&errors, 1)
					if cfg.StopOnErrors > 0 && atomic.LoadInt64(&errors) >= int64(cfg.StopOnErrors) {
						colors.Error.Println("[!] Error threshold reached, stopping worker")
						return
					}
				}

				atomic.AddInt64(&completed, 1)
				if bar != nil {
					bar.Add(1)
				}

				if cfg.Delay > 0 {
					jitter := 0.0
					if cfg.Jitter > 0 {
						jitter = cfg.Delay * cfg.Jitter * (rand.Float64()*2 - 1)
					}
					select {
					case <-time.After(time.Duration((cfg.Delay + jitter) * float64(time.Second))):
					case <-ctx.Done():
						return
					}
				}
			}
		}(i)
	}

	wg.Wait()
	if bar != nil {
		bar.Finish()
	}

	return findings, atomic.LoadInt64(&completed)
}

func executeTask(ctx context.Context, client *http.Client, cfg *Config, baseline *StatisticalBaseline, soft404 *Soft404Detector, template string, task Task, workerID int) Finding {
	f := Finding{
		ID:        task.Index + 1,
		Timestamp: time.Now().Format(time.RFC3339),
		URL:       task.Target,
		Payload:   strings.Join(task.Payload, " | "),
	}

	rawReq := template
	for i, payload := range task.Payload {
		marker := fmt.Sprintf("FUZZ%d", i+1)
		if i == 0 {
			marker = "FUZZ"
		}
		encodedPayload := applyEncoding(payload, cfg.Encoding)
		rawReq = strings.ReplaceAll(rawReq, marker, encodedPayload)
	}

	method := "GET"
	if len(cfg.Methods) > 0 {
		method = cfg.Methods[task.Index%len(cfg.Methods)]
	}
	f.Method = method

	// Retry loop with exponential backoff
	var resp *http.Response
	var body []byte

	for attempt := 0; attempt <= cfg.RetryCount; attempt++ {
		req, err := buildHTTPRequestAdvanced(task.Target, rawReq, method)
		if err != nil {
			f.AnomalyReasons = []string{"BUILD_ERROR"}
			f.RawRequest = rawReq
			return f
		}

		if cfg.RandomAgent {
			req.Header.Set("User-Agent", uaList[rand.Intn(len(uaList))])
		} else if len(uaList) > 0 {
			req.Header.Set("User-Agent", uaList[task.Index%len(uaList)])
		}

		applyEvasion(req, cfg, task.Index)

		t0 := time.Now()
		resp, err = client.Do(req.WithContext(ctx))
		lat := time.Since(t0).Milliseconds()
		f.LatencyMs = lat

		if err != nil {
			if attempt == cfg.RetryCount {
				f.AnomalyReasons = []string{"CONNECTION_ERROR"}
				f.RawRequest = rawReq
				return f
			}
			if cfg.RetryDelay > 0 {
				time.Sleep(time.Duration(cfg.RetryDelay*(attempt+1)) * time.Second)
			}
			continue
		}

		body, err = io.ReadAll(io.LimitReader(resp.Body, 524288))
		resp.Body.Close()
		if err != nil {
			if attempt == cfg.RetryCount {
				f.AnomalyReasons = []string{"READ_ERROR"}
				f.RawRequest = rawReq
				return f
			}
			continue
		}
		break
	}

	bodyStr := string(body)
	f.StatusCode = resp.StatusCode
	f.ResponseSize = len(body)
	f.Words = len(strings.Fields(bodyStr))
	f.Lines = len(strings.Split(bodyStr, "\n"))
	f.ContentHash = fnvHash(bodyStr)

	if baseline.SizeStats != nil && baseline.SizeStats.Mean > 0 {
		f.SizeDeltaPct = (float64(f.ResponseSize)-baseline.SizeStats.Mean)/baseline.SizeStats.Mean*100
	}
	if baseline.WordStats != nil && baseline.WordStats.Mean > 0 {
		f.WordDeltaPct = (float64(f.Words)-baseline.WordStats.Mean)/baseline.WordStats.Mean*100
	}
	if baseline.LineStats != nil && baseline.LineStats.Mean > 0 {
		f.LineDeltaPct = (float64(f.Lines)-baseline.LineStats.Mean)/baseline.LineStats.Mean*100
	}
	if baseline.LatencyStats != nil {
		f.LatencyDeltaMs = f.LatencyMs - int64(baseline.LatencyStats.Median)
	}

	if loc := resp.Header.Get("Location"); loc != "" {
		f.RedirectURL = loc
	}

	payloadStr := strings.Join(task.Payload, "")
	calculateAnomalyScore(&f, cfg, baseline, soft404, payloadStr, bodyStr)

	if cfg.Soft404Detect && soft404 != nil && f.StatusCode == 404 {
		soft404.Add(task.Target, bodyStr)
	}

	f.MatchFilters = checkMatchFilters(f, cfg)

	if f.IsAnomaly || len(f.MatchFilters) > 0 {
		f.ResponsePreview = truncate(bodyStr, cfg.PreviewLength)
		f.RawRequest = rawReq
		if cfg.SaveResponses {
			f.RawResponse = bodyStr
		}
	}

	return f
}

// ============================================================================
// Anomaly Scoring
// ============================================================================

func calculateAnomalyScore(f *Finding, cfg *Config, baseline *StatisticalBaseline, soft404 *Soft404Detector, payload, bodyStr string) {
	var score float64
	var reasons []string

	// 1. Size anomaly (Z-score)
	if baseline.SizeStats != nil && baseline.SizeStats.StdDev > 0 {
		zSize := math.Abs(float64(f.ResponseSize)-baseline.SizeStats.Mean) / baseline.SizeStats.StdDev
		if zSize > 1.5 {
			score += math.Min(zSize, 5.0)
			if float64(f.ResponseSize) > baseline.SizeStats.Mean {
				reasons = append(reasons, "SIZE_SPIKE")
			} else {
				reasons = append(reasons, "SIZE_DROP")
			}
		}
	} else if baseline.SizeStats != nil && baseline.SizeStats.Median > 0 {
		if f.ResponseSize != int(baseline.SizeStats.Median) {
			score += 1.0
			reasons = append(reasons, "SIZE_CHANGE")
		}
	}

	// 2. Word anomaly
	if baseline.WordStats != nil && baseline.WordStats.StdDev > 0 {
		zWords := math.Abs(float64(f.Words)-baseline.WordStats.Mean) / baseline.WordStats.StdDev
		if zWords > 1.5 {
			score += math.Min(zWords, 3.0)
			reasons = append(reasons, "WORD_ANOMALY")
		}
	}

	// 3. Latency anomaly (ratio-based)
	if baseline.LatencyStats != nil && baseline.LatencyStats.Median > 50 {
		latRatio := float64(f.LatencyMs) / baseline.LatencyStats.Median
		if latRatio > 2.5 && f.LatencyMs > 500 {
			score += math.Min(latRatio, 4.0)
			reasons = append(reasons, "TIME_DELAY")
		}
	}

	// 4. Server errors
	if f.StatusCode >= 500 {
		score += 2.0
		reasons = append(reasons, fmt.Sprintf("SERVER_ERROR_%d", f.StatusCode))
	}

	// 5. Error signatures (regex)
	bodyLower := strings.ToLower(bodyStr)
	for _, sig := range errorSigs {
		if matched, _ := regexp.MatchString(sig, bodyLower); matched {
			score += 2.5
			reasons = append(reasons, "SIG_MATCH")
			break
		}
	}

	// 6. WAF/Rate limit
	if f.StatusCode == 403 || f.StatusCode == 429 || f.StatusCode == 406 {
		score += 0.5
		reasons = append(reasons, "WAF_BLOCKED")
	}

	// 7. Reflection
	if payload != "" && strings.Contains(bodyLower, strings.ToLower(payload)) {
		score += 1.0
		reasons = append(reasons, "REFLECTED")
	}

	// 8. Redirect with payload
	if f.RedirectURL != "" && strings.Contains(strings.ToLower(f.RedirectURL), strings.ToLower(payload)) {
		score += 1.0
		reasons = append(reasons, "REDIRECT_WITH_PAYLOAD")
	}

	// 9. Soft 404
	if soft404 != nil && soft404.IsSoft404(f.URL, bodyStr) {
		score += 1.0
		reasons = append(reasons, "SOFT_404")
	}

	// 10. Novel content
	if baseline.HashFreq != nil && baseline.HashFreq[f.ContentHash] == 0 {
		score += 0.5
		reasons = append(reasons, "NOVEL_CONTENT")
	}

	// 11. Diff engine
	if cfg.DiffEngine && len(baseline.SampleBodies) > 0 {
		maxSim := 0.0
		for _, sample := range baseline.SampleBodies {
			sim := jaccardSimilarity(bodyStr, sample)
			if sim > maxSim {
				maxSim = sim
			}
		}
		if maxSim < 0.3 && f.StatusCode == 200 {
			score += 0.5
			reasons = append(reasons, "DIFF_HIGH")
		}
	}

	f.AnomalyScore = score
	f.AnomalyReasons = reasons
	f.IsAnomaly = score >= cfg.AnomalyThreshold
}

// ============================================================================
// Filter System
// ============================================================================

func shouldSkip(f Finding, cfg *Config) bool {
	if len(cfg.MatchStatus) > 0 && !contains(cfg.MatchStatus, f.StatusCode) {
		return true
	}
	if len(cfg.MatchSize) > 0 && !contains(cfg.MatchSize, f.ResponseSize) {
		return true
	}
	if len(cfg.MatchWords) > 0 && !contains(cfg.MatchWords, f.Words) {
		return true
	}
	if len(cfg.MatchLines) > 0 && !contains(cfg.MatchLines, f.Lines) {
		return true
	}
	if cfg.MatchRegex != "" {
		re, _ := regexp.Compile(cfg.MatchRegex)
		if re != nil && !re.MatchString(f.ResponsePreview) {
			return true
		}
	}
	if cfg.MatchTime > 0 && f.LatencyMs < cfg.MatchTime {
		return true
	}

	filterResults := []bool{}

	if len(cfg.FilterStatus) > 0 {
		filterResults = append(filterResults, contains(cfg.FilterStatus, f.StatusCode))
	}
	if len(cfg.FilterSize) > 0 {
		filterResults = append(filterResults, contains(cfg.FilterSize, f.ResponseSize))
	}
	if len(cfg.FilterWords) > 0 {
		filterResults = append(filterResults, contains(cfg.FilterWords, f.Words))
	}
	if len(cfg.FilterLines) > 0 {
		filterResults = append(filterResults, contains(cfg.FilterLines, f.Lines))
	}
	if cfg.FilterRegex != "" {
		re, _ := regexp.Compile(cfg.FilterRegex)
		if re != nil {
			filterResults = append(filterResults, re.MatchString(f.ResponsePreview))
		}
	}
	if cfg.FilterTime > 0 {
		filterResults = append(filterResults, f.LatencyMs > cfg.FilterTime)
	}

	if len(filterResults) > 0 {
		switch cfg.FilterMode {
		case "and":
			allTrue := true
			for _, r := range filterResults {
				if !r {
					allTrue = false
					break
				}
			}
			if allTrue {
				return true
			}
		default:
			for _, r := range filterResults {
				if r {
					return true
				}
			}
		}
	}

	return false
}

func checkMatchFilters(f Finding, cfg *Config) []string {
	var matches []string
	if len(cfg.MatchStatus) > 0 && contains(cfg.MatchStatus, f.StatusCode) {
		matches = append(matches, fmt.Sprintf("status:%d", f.StatusCode))
	}
	if len(cfg.MatchSize) > 0 && contains(cfg.MatchSize, f.ResponseSize) {
		matches = append(matches, fmt.Sprintf("size:%d", f.ResponseSize))
	}
	if len(cfg.MatchWords) > 0 && contains(cfg.MatchWords, f.Words) {
		matches = append(matches, fmt.Sprintf("words:%d", f.Words))
	}
	if len(cfg.MatchLines) > 0 && contains(cfg.MatchLines, f.Lines) {
		matches = append(matches, fmt.Sprintf("lines:%d", f.Lines))
	}
	return matches
}

func autoCalibrateFilters(cfg *Config, baseline *StatisticalBaseline) {
	if baseline.SizeStats != nil && baseline.SizeStats.Mean > 0 {
		cfg.FilterSize = append(cfg.FilterSize, int(baseline.SizeStats.Mean))
		colors.Info.Printf("[+] Auto-calibrated filter size: %.0f bytes\n", baseline.SizeStats.Mean)
	}
	if baseline.WordStats != nil && baseline.WordStats.Mean > 0 {
		cfg.FilterWords = append(cfg.FilterWords, int(baseline.WordStats.Mean))
		colors.Info.Printf("[+] Auto-calibrated filter words: %.0f\n", baseline.WordStats.Mean)
	}
	if baseline.LineStats != nil && baseline.LineStats.Mean > 0 {
		cfg.FilterLines = append(cfg.FilterLines, int(baseline.LineStats.Mean))
		colors.Info.Printf("[+] Auto-calibrated filter lines: %.0f\n", baseline.LineStats.Mean)
	}
}

// ============================================================================
// Statistical Calibration
// ============================================================================

func calibrateStatistical(client *http.Client, cfg *Config, template, target string) *StatisticalBaseline {
	var profiles []ResponseProfile
	var bodies []string

	calibratePayloads := []string{
		"CALIBRATE_JFUXX_001", "RANDOM_TEST_456_ABC", "NOT_EXIST_789_XYZ",
		"JFUXX_CALIBRATE_123", "TEST_PAYLOAD_000_QWE", "CALIBRATE_JFUXX_002",
		"RANDOM_TEST_789_DEF", "NOT_EXIST_123_GHI", "JFUXX_CALIBRATE_456",
		"TEST_PAYLOAD_999_JKL", "CALIBRATE_JFUXX_003", "RANDOM_TEST_111_MNO",
	}

	rounds := cfg.CalibrateRounds
	if rounds <= 0 {
		rounds = 10
	}
	if rounds > len(calibratePayloads) {
		rounds = len(calibratePayloads)
	}

	for i := 0; i < rounds; i++ {
		payload := calibratePayloads[i%len(calibratePayloads)]
		rawReq := strings.ReplaceAll(template, "FUZZ", payload)

		req, err := buildHTTPRequestAdvanced(target, rawReq, "GET")
		if err != nil {
			continue
		}

		if len(uaList) > 0 {
			req.Header.Set("User-Agent", uaList[0])
		}

		t0 := time.Now()
		resp, err := client.Do(req)
		latency := time.Since(t0).Milliseconds()

		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 262144))
		resp.Body.Close()
		bodyStr := string(body)

		profiles = append(profiles, ResponseProfile{
			StatusCode:  resp.StatusCode,
			Size:        len(body),
			Words:       len(strings.Fields(bodyStr)),
			Lines:       len(strings.Split(bodyStr, "\n")),
			LatencyMs:   latency,
			ContentHash: fnvHash(bodyStr),
		})
		bodies = append(bodies, bodyStr)

		if cfg.Delay > 0 {
			time.Sleep(time.Duration(cfg.Delay * float64(time.Second)))
		} else {
			time.Sleep(100 * time.Millisecond)
		}
	}

	if len(profiles) == 0 {
		return &StatisticalBaseline{
			SizeStats:    &ResponseStats{Mean: 0, Median: 0, StdDev: 0},
			LatencyStats: &ResponseStats{Mean: 100, Median: 100, StdDev: 0},
		}
	}

	sizes := make([]float64, len(profiles))
	words := make([]float64, len(profiles))
	lines := make([]float64, len(profiles))
	lats := make([]float64, len(profiles))
	hashFreq := make(map[string]int)

	for i, p := range profiles {
		sizes[i] = float64(p.Size)
		words[i] = float64(p.Words)
		lines[i] = float64(p.Lines)
		lats[i] = float64(p.LatencyMs)
		hashFreq[p.ContentHash]++
	}

	sizes = filterOutliers(sizes)
	words = filterOutliers(words)
	lines = filterOutliers(lines)
	lats = filterOutliers(lats)

	return &StatisticalBaseline{
		SizeStats:    calculateStats(sizes),
		WordStats:    calculateStats(words),
		LineStats:    calculateStats(lines),
		LatencyStats: calculateStats(lats),
		HashFreq:     hashFreq,
		Profiles:     profiles,
		SampleBodies: bodies,
	}
}

func calculateStats(values []float64) *ResponseStats {
	if len(values) == 0 {
		return &ResponseStats{}
	}
	sort.Float64s(values)
	n := len(values)

	mean := 0.0
	for _, v := range values {
		mean += v
	}
	mean /= float64(n)

	var median float64
	if n%2 == 0 {
		median = (values[n/2-1] + values[n/2]) / 2
	} else {
		median = values[n/2]
	}

	q1 := percentile(values, 25)
	q3 := percentile(values, 75)
	iqr := q3 - q1

	variance := 0.0
	for _, v := range values {
		variance += math.Pow(v-mean, 2)
	}
	variance /= float64(n)
	stddev := math.Sqrt(variance)

	return &ResponseStats{
		Mean: mean, Median: median, StdDev: stddev,
		Q1: q1, Q3: q3, IQR: iqr,
		Values: append([]float64{}, values...),
	}
}

func filterOutliers(values []float64) []float64 {
	if len(values) < 4 {
		return values
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	q1 := percentile(sorted, 25)
	q3 := percentile(sorted, 75)
	iqr := q3 - q1
	lower := q1 - 1.5*iqr
	upper := q3 + 1.5*iqr

	var filtered []float64
	for _, v := range values {
		if v >= lower && v <= upper {
			filtered = append(filtered, v)
		}
	}
	if len(filtered) == 0 {
		return values
	}
	return filtered
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	index := (p / 100.0) * float64(len(sorted)-1)
	lower := int(math.Floor(index))
	upper := int(math.Ceil(index))
	weight := index - float64(lower)
	if upper >= len(sorted) {
		return sorted[lower]
	}
	return sorted[lower]*(1-weight) + sorted[upper]*weight
}

// ============================================================================
// Recursion
// ============================================================================

func extractRecursionSeeds(findings []Finding, cfg *Config) []string {
	seen := make(map[string]bool)
	var seeds []string

	for _, f := range findings {
		if len(cfg.RecursionStatus) > 0 && !contains(cfg.RecursionStatus, f.StatusCode) {
			continue
		}
		u, err := url.Parse(f.URL)
		if err != nil {
			continue
		}

		pathStr := u.Path
		if !strings.HasSuffix(pathStr, "/") {
			pathStr = path.Dir(pathStr) + "/"
		}
		if pathStr == "/" || pathStr == "" {
			continue
		}

		u.Path = pathStr
		u.RawQuery = ""
		u.Fragment = ""
		seed := u.String()

		if !seen[seed] {
			seen[seed] = true
			seeds = append(seeds, seed)
		}
	}
	return seeds
}

// ============================================================================
// Payload Generation
// ============================================================================

func generatePayloads(wordlists [][]string, extensions []string) [][]string {
	if len(wordlists) == 0 {
		return nil
	}

	result := [][]string{}

	var generate func(int, []string)
	generate = func(depth int, current []string) {
		if depth == len(wordlists) {
			if len(extensions) > 0 && len(current) > 0 {
				for _, ext := range extensions {
					newCurrent := append([]string{}, current...)
					newCurrent[len(newCurrent)-1] = newCurrent[len(newCurrent)-1] + ext
					result = append(result, newCurrent)
				}
			}
			result = append(result, append([]string{}, current...))
			return
		}

		for _, word := range wordlists[depth] {
			generate(depth+1, append(current, word))
		}
	}

	generate(0, []string{})
	return result
}

func loadWordlists(paths []string) [][]string {
	var result [][]string
	for _, path := range paths {
		words, err := readWordlist(path)
		if err != nil {
			colors.Warning.Printf("[!] Failed to load %s: %v\n", path, err)
			continue
		}
		result = append(result, words)
		colors.Info.Printf("[+] Loaded %s: %d payloads\n", path, len(words))
	}
	return result
}

// ============================================================================
// Output Functions
// ============================================================================

func saveReport(report *Report, outDir, format string) {
	now := time.Now()
	filename := fmt.Sprintf("session_%02d%02d_%02d%02d_%04d.%s",
		now.Hour(), now.Minute(), now.Day(), now.Month(), now.Year(), format)
	outPath := filepath.Join(outDir, filename)

	switch format {
	case "json":
		data, _ := json.MarshalIndent(report, "", "  ")
		os.WriteFile(outPath, data, 0644)
	case "csv":
		writeCSV(report, outPath)
	case "html":
		writeHTML(report, outPath)
	case "md":
		writeMarkdown(report, outPath)
	}

	absPath, _ := filepath.Abs(outPath)
	colors.Success.Printf("[+] %s report: %s\n", strings.ToUpper(format), absPath)
}

func writeCSV(report *Report, path string) {
	file, _ := os.Create(path)
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"ID", "URL", "Method", "Payload", "Status", "Size", "Words", "Lines", "Latency", "Anomaly", "Score", "Reasons"})
	for _, h := range report.Hits {
		writer.Write([]string{
			strconv.Itoa(h.ID), h.URL, h.Method, h.Payload,
			strconv.Itoa(h.StatusCode), strconv.Itoa(h.ResponseSize),
			strconv.Itoa(h.Words), strconv.Itoa(h.Lines),
			strconv.FormatInt(h.LatencyMs, 10),
			strconv.FormatBool(h.IsAnomaly),
			fmt.Sprintf("%.1f", h.AnomalyScore),
			strings.Join(h.AnomalyReasons, ";"),
		})
	}
}

func writeHTML(report *Report, path string) {
	tmpl := `<!DOCTYPE html>
<html>
<head><title>JFuxx Pro Report</title>
<style>
body{font-family:Arial,sans-serif;margin:20px;background:#f5f5f5}
.container{max-width:1400px;margin:0 auto;background:white;padding:20px;border-radius:8px}
h1{color:#333}table{width:100%;border-collapse:collapse;margin-top:20px}
th,td{padding:12px;text-align:left;border-bottom:1px solid #ddd}
th{background:#4CAF50;color:white}
tr:hover{background:#f1f1f1}
.hit{background:#ffebee}
.score{font-weight:bold;color:#d32f2f}
.reason{color:#666;font-size:0.9em}
</style></head>
<body>
<div class="container">
<h1>JFuxx Pro Scan Report</h1>
<p>Target: {{.Session.Target}} | Requests: {{.Session.TotalReqs}} | Hits: {{.Session.TotalHits}} | RPS: {{printf "%.1f" .Session.RPS}}</p>
<table>
<tr><th>ID</th><th>Payload</th><th>Status</th><th>Size</th><th>Words</th><th>Latency</th><th>Score</th><th>Reasons</th></tr>
{{range .Hits}}
<tr class="hit">
<td>{{.ID}}</td><td>{{.Payload}}</td><td>{{.StatusCode}}</td>
<td>{{.ResponseSize}} bytes</td><td>{{.Words}}</td><td>{{.LatencyMs}}ms</td>
<td class="score">{{printf "%.1f" .AnomalyScore}}</td>
<td class="reason">{{range .AnomalyReasons}}{{.}} {{end}}</td>
</tr>
{{end}}
</table></div></body></html>`

	file, _ := os.Create(path)
	defer file.Close()
	t := template.Must(template.New("report").Parse(tmpl))
	t.Execute(file, report)
}

func writeMarkdown(report *Report, path string) {
	var sb strings.Builder
	sb.WriteString("# JFuxx Pro Scan Report\n\n")
	sb.WriteString(fmt.Sprintf("- **Target**: %s\n", report.Session.Target))
	sb.WriteString(fmt.Sprintf("- **Time**: %s - %s\n", report.Session.StartTime, report.Session.EndTime))
	sb.WriteString(fmt.Sprintf("- **Duration**: %s\n", report.Session.Duration))
	sb.WriteString(fmt.Sprintf("- **Requests**: %d (%.1f req/s)\n", report.Session.TotalReqs, report.Session.RPS))
	sb.WriteString(fmt.Sprintf("- **Hits**: %d\n\n", report.Session.TotalHits))

	sb.WriteString("## Results\n\n")
	sb.WriteString("| ID | Payload | Status | Size | Words | Lines | Latency | Score | Reasons |\n")
	sb.WriteString("|---|---|---|---|---|---|---|---|---|\n")

	for _, h := range report.Hits {
		payload := h.Payload
		if len(payload) > 50 {
			payload = payload[:50] + "..."
		}
		sb.WriteString(fmt.Sprintf("| %d | `%s` | %d | %d | %d | %d | %dms | %.1f | %s |\n",
			h.ID, payload, h.StatusCode, h.ResponseSize, h.Words, h.Lines, h.LatencyMs, h.AnomalyScore,
			strings.Join(h.AnomalyReasons, ", ")))
	}

	os.WriteFile(path, []byte(sb.String()), 0644)
}

// ============================================================================
// Replay and Response Functions
// ============================================================================

func writeCurlScripts(hits []Finding, outDir string) {
	curlDir := filepath.Join(outDir, "replay", "curl")
	os.MkdirAll(curlDir, 0755)

	for _, h := range hits {
		if h.RawRequest == "" {
			continue
		}
		lines := strings.Split(h.RawRequest, "\n")
		if len(lines) == 0 {
			continue
		}

		var curlCmd strings.Builder
		curlCmd.WriteString("#!/bin/bash\n")
		curlCmd.WriteString(fmt.Sprintf("# Hit ID: %d\n", h.ID))
		curlCmd.WriteString(fmt.Sprintf("# Reasons: %s\n", strings.Join(h.AnomalyReasons, ", ")))
		curlCmd.WriteString(fmt.Sprintf("# Score: %.1f\n", h.AnomalyScore))
		curlCmd.WriteString("curl -i -s -k ")

		for i, line := range lines {
			if i == 0 {
				continue
			}
			if line == "" {
				break
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				curlCmd.WriteString(fmt.Sprintf("-H '%s: %s' ", strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])))
			}
		}

		bodyIdx := strings.Index(h.RawRequest, "\n\n")
		if bodyIdx != -1 {
			body := h.RawRequest[bodyIdx+2:]
			body = strings.TrimSpace(body)
			if body != "" {
				curlCmd.WriteString(fmt.Sprintf("-d '%s' ", strings.ReplaceAll(body, "'", "'\''")))
			}
		}

		curlCmd.WriteString(fmt.Sprintf("'%s'\n", h.URL))

		name := fmt.Sprintf("hit_%04d_curl.sh", h.ID)
		path := filepath.Join(curlDir, name)
		os.WriteFile(path, []byte(curlCmd.String()), 0755)
	}
}

func saveResponse(f Finding, outDir string) {
	data := f.ResponsePreview
	if f.RawResponse != "" {
		data = f.RawResponse
	}
	if data == "" {
		return
	}
	name := fmt.Sprintf("response_%04d_%s.html", f.ID, sanitize(f.Payload))
	path := filepath.Join(outDir, "responses", name)
	os.WriteFile(path, []byte(data), 0644)
}

func writeReplayFiles(hits []Finding, outDir string) {
	replayDir := filepath.Join(outDir, "replay")
	os.MkdirAll(replayDir, 0755)

	for _, h := range hits {
		if !h.IsAnomaly || h.RawRequest == "" {
			continue
		}
		name := fmt.Sprintf("hit_%04d_%s.txt", h.ID, sanitize(h.Payload))
		path := filepath.Join(replayDir, name)
		os.WriteFile(path, []byte(h.RawRequest), 0644)
	}
}

func printFinding(f Finding, cfg *Config) {
	payload := f.Payload
	if len(payload) > 40 {
		payload = payload[:40] + "..."
	}

	statusColor := colors.Info
	if f.StatusCode >= 500 {
		statusColor = colors.Error
	} else if f.StatusCode == 403 || f.StatusCode == 401 {
		statusColor = colors.Warning
	} else if f.StatusCode == 200 {
		statusColor = colors.Success
	}

	reasonStr := strings.Join(f.AnomalyReasons, ", ")
	if len(reasonStr) > 30 {
		reasonStr = reasonStr[:30] + "..."
	}

	fmt.Printf("\r[#%04d] %s | %s | %6d b (%+5.1f%%) | %5dms | Score: %.1f | %s\n",
		f.ID,
		statusColor.Sprintf("%3d", f.StatusCode),
		colors.Muted.Sprintf("%-40s", payload),
		f.ResponseSize,
		f.SizeDeltaPct,
		f.LatencyMs,
		f.AnomalyScore,
		colors.Warning.Sprintf("%s", reasonStr),
	)
}

func printSummary(r *Report) {
	fmt.Println("\n====================================================")
	fmt.Println("           JFuxx Pro Scan Complete")
	fmt.Println("====================================================")
	fmt.Printf("Duration:    %s\n", r.Session.Duration)
	fmt.Printf("Requests:    %d (%.1f req/s)\n", r.Session.TotalReqs, r.Session.RPS)
	fmt.Printf("Hits:        %d\n", r.Session.TotalHits)

	if len(r.Hits) > 0 {
		sort.Slice(r.Hits, func(i, j int) bool {
			return r.Hits[i].AnomalyScore > r.Hits[j].AnomalyScore
		})

		fmt.Println("\n--- TOP HITS (sorted by anomaly score) ---")
		for i, h := range r.Hits {
			if i >= 20 {
				fmt.Printf("... and %d more\n", len(r.Hits)-20)
				break
			}
			payload := h.Payload
			if len(payload) > 35 {
				payload = payload[:35] + "..."
			}
			reasons := strings.Join(h.AnomalyReasons, ", ")
			if len(reasons) > 40 {
				reasons = reasons[:40] + "..."
			}
			fmt.Printf("  [#%04d] %-35s | %3d | %6d b | %5dms | Score: %.1f | %s\n",
				h.ID, payload, h.StatusCode, h.ResponseSize, h.LatencyMs, h.AnomalyScore, reasons)
		}
	}

	fmt.Println("\n--- Status Distribution ---")
	keys := make([]string, 0, len(r.Statistics.ByStatusCode))
	for k := range r.Statistics.ByStatusCode {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  HTTP %s: %d\n", k, r.Statistics.ByStatusCode[k])
	}

	if len(r.Statistics.ByAnomalyReason) > 0 {
		fmt.Println("\n--- Anomaly Breakdown ---")
		for reason, count := range r.Statistics.ByAnomalyReason {
			fmt.Printf("  %s: %d\n", reason, count)
		}
	}
}

// ============================================================================
// Encoding & Hashing
// ============================================================================

func applyEncoding(payload, encoding string) string {
	if encoding == "" {
		return payload
	}
	encoders := strings.Split(encoding, "|")
	result := payload
	for _, enc := range encoders {
		enc = strings.TrimSpace(enc)
		switch enc {
		case "url":
			result = url.QueryEscape(result)
		case "doubleurl":
			result = url.QueryEscape(url.QueryEscape(result))
		case "base64":
			result = base64.StdEncoding.EncodeToString([]byte(result))
		case "hex":
			result = hex.EncodeToString([]byte(result))
		case "html":
			result = html.EscapeString(result)
		case "unicode":
			result = unicodeEscape(result)
		case "none", "":
			// no-op
		}
	}
	return result
}

func unicodeEscape(s string) string {
	var b strings.Builder
	for _, c := range s {
		b.WriteString(fmt.Sprintf("\u%04x", c))
	}
	return b.String()
}

func fnvHash(s string) string {
	h := fnv.New64a()
	h.Write([]byte(s))
	return fmt.Sprintf("%016x", h.Sum64())
}

func jaccardSimilarity(a, b string) float64 {
	wordsA := strings.Fields(a)
	wordsB := strings.Fields(b)

	setA := make(map[string]bool)
	setB := make(map[string]bool)

	for _, w := range wordsA {
		setA[w] = true
	}
	for _, w := range wordsB {
		setB[w] = true
	}

	intersection := 0
	for w := range setA {
		if setB[w] {
			intersection++
		}
	}
	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 1.0
	}
	return float64(intersection) / float64(union)
}

// ============================================================================
// WAF Evasion
// ============================================================================

func applyEvasion(req *http.Request, cfg *Config, taskIndex int) {
	if cfg.EvasionLevel <= 0 {
		return
	}

	if cfg.EvasionLevel >= 1 {
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.%d.%d.%d, 172.16.%d.%d",
			rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256)))
		req.Header.Set("X-Real-Ip", fmt.Sprintf("10.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256)))

		accepts := []string{
			"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
			"*/*",
		}
		req.Header.Set("Accept", accepts[rand.Intn(len(accepts))])
	}

	if cfg.EvasionLevel >= 2 {
		req.Header.Set("Accept-Language", "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7")
		req.Header.Set("Cache-Control", "max-age=0")
		req.Header.Set("DNT", "1")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("X-Request-ID", fmt.Sprintf("%08x", rand.Intn(0xFFFFFFFF)))
	}
}

// ============================================================================
// Rate Limiter
// ============================================================================

type RateLimiter struct {
	ticker *time.Ticker
}

func NewRateLimiter(rps int) *RateLimiter {
	if rps <= 0 {
		return nil
	}
	return &RateLimiter{
		ticker: time.NewTicker(time.Second / time.Duration(rps)),
	}
}

func (rl *RateLimiter) Wait() {
	if rl == nil || rl.ticker == nil {
		return
	}
	<-rl.ticker.C
}

// ============================================================================
// Parsing and Utility Functions
// ============================================================================

func parseFlags() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.Target, "u", "", "Target URL")
	flag.StringVar(&cfg.TargetsFile, "U", "", "Targets file")
	flag.StringVar(&cfg.RequestFile, "r", "", "HTTP request file (supports FUZZ, FUZ2Z, FUZ3Z)")
	flag.StringVar(&cfg.Proxy, "x", "", "Proxy URL")
	flag.StringVar(&cfg.OutputDir, "o", "output", "Output directory")
	flag.StringVar(&cfg.OutputFormat, "of", "json", "Output format: json, csv, html, md, all")
	flag.IntVar(&cfg.Workers, "c", 40, "Concurrent workers")
	flag.IntVar(&cfg.Timeout, "timeout", 10, "Timeout in seconds")
	flag.Float64Var(&cfg.Delay, "p", 0, "Delay between requests (seconds)")
	flag.Float64Var(&cfg.Jitter, "jitter", 0, "Delay jitter ratio (0-1)")
	flag.IntVar(&cfg.RateLimit, "rate", 0, "Max requests per second")
	flag.IntVar(&cfg.RetryCount, "retries", 0, "Retry count")
	flag.IntVar(&cfg.RetryDelay, "retry-delay", 1, "Base retry delay (seconds)")
	flag.IntVar(&cfg.MaxTime, "maxtime", 0, "Max execution time (seconds)")
	flag.BoolVar(&cfg.Recursion, "recursion", false, "Enable recursion")
	flag.IntVar(&cfg.RecursionDepth, "recursion-depth", 0, "Recursion depth")
	flag.StringVar(&cfg.FilterMode, "fmode", "or", "Filter mode: and, or")
	flag.BoolVar(&cfg.RandomAgent, "random-agent", false, "Random User-Agent")
	flag.StringVar(&cfg.Encoding, "enc", "", "Encoding: url, doubleurl, hex, html, unicode, or chained (url|base64|hex)")
	flag.BoolVar(&cfg.SaveResponses, "sr", false, "Save full responses")
	flag.IntVar(&cfg.PreviewLength, "pl", 800, "Response preview length")
	flag.BoolVar(&cfg.Quiet, "s", false, "Silent mode")
	flag.BoolVar(&cfg.HideProgress, "np", false, "Hide progress bar")
	flag.BoolVar(&cfg.StopOnSuccess, "sf", false, "Stop on first hit")
	flag.IntVar(&cfg.StopOnErrors, "se", 0, "Stop after N errors")
	flag.BoolVar(&cfg.FilterAutoCal, "acc", false, "Auto-calibrate filters")

	filterStatus := flag.String("fc", "", "Filter status codes (comma-separated)")
	filterSize := flag.String("fs", "", "Filter sizes (comma-separated)")
	filterWords := flag.String("fw", "", "Filter word counts (comma-separated)")
	filterLines := flag.String("fl", "", "Filter line counts (comma-separated)")
	filterRegex := flag.String("fr", "", "Filter regex")
	filterTime := flag.Int("ft", 0, "Filter min response time (ms)")

	matchStatus := flag.String("mc", "", "Match status codes")
	matchSize := flag.String("ms", "", "Match sizes")
	matchWords := flag.String("mw", "", "Match word counts")
	matchLines := flag.String("ml", "", "Match line counts")
	matchRegex := flag.String("mr", "", "Match regex")
	matchTime := flag.Int("mt", 0, "Match min response time (ms)")

	var wordlists multiStringFlag
	flag.Var(&wordlists, "w", "Wordlist file (can be specified multiple times)")

	var extensions multiStringFlag
	flag.Var(&extensions, "e", "Append extensions (can be specified multiple times)")

	var methods multiStringFlag
	flag.Var(&methods, "X", "HTTP methods (can be specified multiple times)")

	// Advanced flags
	flag.IntVar(&cfg.EvasionLevel, "evasion", 0, "WAF evasion level: 0=none, 1=basic, 2=aggressive")
	flag.IntVar(&cfg.CalibrateRounds, "cal-rounds", 10, "Baseline calibration rounds")
	flag.Float64Var(&cfg.AnomalyThreshold, "threshold", 2.0, "Anomaly score threshold")
	flag.BoolVar(&cfg.Soft404Detect, "soft404", false, "Enable soft-404 detection")
	flag.BoolVar(&cfg.FollowRedirects, "follow", false, "Follow redirects")
	flag.BoolVar(&cfg.HTTP2, "http2", false, "Force HTTP/2")
	flag.BoolVar(&cfg.DiffEngine, "diff", false, "Enable response diff engine")

	recursionStatus := flag.String("recursion-status", "200,301,302,307,308", "Recursion status codes")

	flag.Parse()

	if len(wordlists) > 0 {
		cfg.Wordlists = wordlists
	}
	if len(extensions) > 0 {
		cfg.Extensions = extensions
	}
	if len(methods) > 0 {
		cfg.Methods = methods
	}

	cfg.FilterStatus = parseIntList(*filterStatus)
	cfg.FilterSize = parseIntList(*filterSize)
	cfg.FilterWords = parseIntList(*filterWords)
	cfg.FilterLines = parseIntList(*filterLines)
	cfg.FilterRegex = *filterRegex
	cfg.FilterTime = int64(*filterTime)

	cfg.MatchStatus = parseIntList(*matchStatus)
	cfg.MatchSize = parseIntList(*matchSize)
	cfg.MatchWords = parseIntList(*matchWords)
	cfg.MatchLines = parseIntList(*matchLines)
	cfg.MatchRegex = *matchRegex
	cfg.MatchTime = int64(*matchTime)

	cfg.RecursionStatus = parseIntList(*recursionStatus)

	return cfg
}

type multiStringFlag []string

func (m *multiStringFlag) String() string { return strings.Join(*m, ", ") }
func (m *multiStringFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func resolveTargets(cfg *Config) []string {
	var targets []string
	if cfg.Target != "" {
		targets = append(targets, cfg.Target)
	}
	if cfg.TargetsFile != "" {
		data, _ := os.ReadFile(cfg.TargetsFile)
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
	}
	return targets
}

func buildHTTPRequestAdvanced(targetURL, raw, method string) (*http.Request, error) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")

	var headers, body string
	if idx := strings.Index(raw, "\n\n"); idx != -1 {
		headers = raw[:idx]
		body = raw[idx+2:]
	} else {
		headers = raw
	}

	lines := strings.Split(headers, "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty request")
	}

	reqParts := strings.Fields(lines[0])
	if len(reqParts) < 2 {
		return nil, fmt.Errorf("bad request line: %s", lines[0])
	}

	if method == "" {
		method = reqParts[0]
	}
	rawURI := reqParts[1]

	base, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(rawURI, "http://") || strings.HasPrefix(rawURI, "https://") {
		uri, err := url.Parse(rawURI)
		if err == nil {
			base.Path = uri.Path
			base.RawQuery = uri.RawQuery
		}
	} else {
		if strings.HasPrefix(rawURI, "/") {
			parts := strings.SplitN(rawURI, "?", 2)
			base.Path = parts[0]
			if len(parts) == 2 {
				base.RawQuery = parts[1]
			}
		} else {
			if base.Path == "" {
				base.Path = "/" + rawURI
			} else if strings.HasSuffix(base.Path, "/") {
				base.Path += rawURI
			} else {
				base.Path += "/" + rawURI
			}
		}
	}

	body = strings.TrimSuffix(body, "\n")
	req, err := http.NewRequestWithContext(context.Background(), method, base.String(), strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		if strings.EqualFold(key, "Connection") ||
			strings.EqualFold(key, "Proxy-Connection") ||
			strings.EqualFold(key, "Accept-Encoding") ||
			strings.EqualFold(key, "Transfer-Encoding") {
			continue
		}
		req.Header.Set(key, val)
	}

	req.Header.Set("Accept-Encoding", "identity")
	req.ContentLength = int64(len(body))
	if body != "" {
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	req.Host = base.Host

	return req, nil
}

func buildClient(cfg *Config) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(cfg.Timeout/2) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 200,
		IdleConnTimeout:     120 * time.Second,
		ForceAttemptHTTP2:   cfg.HTTP2,
	}
	if cfg.Proxy != "" {
		if p, err := url.Parse(cfg.Proxy); err == nil {
			tr.Proxy = http.ProxyURL(p)
		}
	}
	return &http.Client{
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if cfg.FollowRedirects {
				return nil
			}
			return http.ErrUseLastResponse
		},
	}
}

func buildReport(cfg *Config, baseline *StatisticalBaseline, findings []Finding, duration time.Duration, total int64, targets []string) *Report {
	r := &Report{}
	r.Session.Target = cfg.Target
	r.Session.Targets = targets
	r.Session.StartTime = time.Now().Add(-duration).Format(time.RFC3339)
	r.Session.EndTime = time.Now().Format(time.RFC3339)
	r.Session.Duration = duration.String()
	r.Session.TotalReqs = total
	r.Session.Workers = cfg.Workers
	r.Session.Wordlists = cfg.Wordlists
	if duration.Seconds() > 0 {
		r.Session.RPS = float64(total) / duration.Seconds()
	}
	r.Baseline.AvgSize = int(baseline.SizeStats.Mean)
	r.Baseline.AvgWords = int(baseline.WordStats.Mean)
	r.Baseline.AvgLines = int(baseline.LineStats.Mean)
	r.Baseline.AvgLatencyMs = int64(baseline.LatencyStats.Median)
	r.Baseline.Responses = baseline.Profiles
	r.Statistics.ByStatusCode = make(map[string]int)
	r.Statistics.BySize = make(map[string]int)
	r.Statistics.ByAnomalyReason = make(map[string]int)
	r.Statistics.ByResponseTime = make(map[string]int)
	r.Statistics.Errors = make(map[string]int)
	r.Config = *cfg

	for _, f := range findings {
		r.Statistics.ByStatusCode[strconv.Itoa(f.StatusCode)]++
		r.Statistics.BySize[strconv.Itoa(f.ResponseSize)]++

		if f.IsAnomaly || len(f.MatchFilters) > 0 {
			r.Hits = append(r.Hits, f)
			r.Session.TotalHits++
			for _, reason := range f.AnomalyReasons {
				r.Statistics.ByAnomalyReason[reason]++
			}
		}
	}

	for _, f := range findings {
		bucket := fmt.Sprintf("%d-%dms", (f.LatencyMs/1000)*1000, ((f.LatencyMs/1000)+1)*1000)
		r.Statistics.ByResponseTime[bucket]++
	}

	return r
}

func readWordlist(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, nil
}

func parseIntList(s string) []int {
	if s == "" {
		return nil
	}
	var out []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if v, err := strconv.Atoi(p); err == nil {
			out = append(out, v)
		}
	}
	return out
}

func contains(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func containsStr(slice []string, val string) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func sanitize(s string) string {
	var out []rune
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			out = append(out, r)
		} else {
			out = append(out, '_')
		}
	}
	if len(out) > 25 {
		out = out[:25]
	}
	return string(out)
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  jfuxx -r request.txt -w wordlist.txt -u http://target.com")
	fmt.Println("")
	fmt.Println("Advanced Usage:")
	fmt.Println("  jfuxx -r req.txt -w paths.txt -w params.txt -u http://target.com")
	fmt.Println("  jfuxx -r req.txt -w dirs.txt -e .php -e .bak -e .old -fc 404")
	fmt.Println("  jfuxx -r req.txt -w sqli.txt -acc -mt 3000 -o results")
	fmt.Println("  jfuxx -r req.txt -w api.txt -rate 10 -jitter 0.5 -random-agent")
	fmt.Println("  jfuxx -r req.txt -w dirs.txt -recursion -recursion-depth 2 -soft404")
	fmt.Println("")
	fmt.Println("Filters:")
	fmt.Println("  -fc 404,500    Filter status codes")
	fmt.Println("  -fs 1234       Filter sizes")
	fmt.Println("  -fw 42         Filter word counts")
	fmt.Println("  -fl 10         Filter line counts")
	fmt.Println("  -fr 'regex'    Filter regex")
	fmt.Println("  -acc           Auto-calibrate filters")
	fmt.Println("")
	fmt.Println("Match:")
	fmt.Println("  -mc 200,302    Match status codes")
	fmt.Println("  -ms 4521       Match sizes")
	fmt.Println("  -mw 100        Match word counts")
	fmt.Println("  -ml 20         Match line counts")
	fmt.Println("  -mr 'regex'    Match regex")
	fmt.Println("  -mt 3000       Match min response time")
	fmt.Println("")
	fmt.Println("Output:")
	fmt.Println("  -of json       Output format (json, csv, html, md, all)")
	fmt.Println("  -sr            Save full responses")
	fmt.Println("  -pl 800        Preview length")
	fmt.Println("")
	fmt.Println("Performance:")
	fmt.Println("  -c 40          Workers")
	fmt.Println("  -rate 10       Max requests per second")
	fmt.Println("  -p 0.1         Delay between requests")
	fmt.Println("  -jitter 0.5    Delay jitter")
	fmt.Println("  -maxtime 3600  Max execution time")
	fmt.Println("  -retries 3     Retry failed requests")
	fmt.Println("  -retry-delay 1 Base retry delay (seconds)")
	fmt.Println("")
	fmt.Println("Advanced:")
	fmt.Println("  -evasion 1     WAF evasion level (0=none, 1=basic, 2=aggressive)")
	fmt.Println("  -cal-rounds 10 Baseline calibration rounds")
	fmt.Println("  -soft404       Enable soft-404 detection")
	fmt.Println("  -follow        Follow redirects")
	fmt.Println("  -http2         Force HTTP/2")
	fmt.Println("  -diff          Enable response diff engine")
	fmt.Println("  -enc url|base64  Chained encoding support")
}
