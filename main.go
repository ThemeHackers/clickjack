package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	ColorReset      = "\033[0m"
	ColorRed        = "\033[31m"
	ColorGreen      = "\033[32m"
	ColorYellow     = "\033[33m"
	ColorBlue       = "\033[34m"
	ColorCyan       = "\033[36m"
	ColorWhite      = "\033[37m"
	ColorDarkOrange = "\033[38;5;208m"
	ColorReverse    = "\033[7m"
)

var cspHelp = map[string]struct {
	Desc  string
	Color string
}{
	"child-src":                   {Desc: "Defines the valid sources for web workers and nested browsing contexts.", Color: ""},
	"connect-src":                 {Desc: "Restricts the URLs which can be loaded using script interfaces.", Color: ""},
	"default-src":                 {Desc: "Serves as a fallback for the other fetch directives.", Color: ""},
	"font-src":                    {Desc: "Specifies valid sources for fonts loaded using @font-face.", Color: ""},
	"frame-src":                   {Desc: "Specifies valid sources for nested browsing contexts (frame, iframe).", Color: ""},
	"img-src":                     {Desc: "Specifies valid sources of images and favicons.", Color: ""},
	"manifest-src":                {Desc: "Specifies valid sources of application manifest files.", Color: ""},
	"media-src":                   {Desc: "Specifies valid sources for loading media (audio, video).", Color: ""},
	"object-src":                  {Desc: "Specifies valid sources for object, embed, and applet elements.", Color: ""},
	"prefetch-src":                {Desc: "Specifies valid sources to be prefetched or prerendered.", Color: ""},
	"script-src":                  {Desc: "Specifies valid sources for JavaScript.", Color: ""},
	"style-src":                   {Desc: "Specifies valid sources for stylesheets.", Color: ""},
	"webrtc-src":                  {Desc: "Specifies valid sources for WebRTC connections.", Color: ""},
	"worker-src":                  {Desc: "Specifies valid sources for Worker scripts.", Color: ""},
	"base-uri":                    {Desc: "Restricts the URLs which can be used in a document's base element.", Color: ""},
	"plugin-types":                {Desc: "Restricts the set of plugins that can be embedded.", Color: ""},
	"sandbox":                     {Desc: "Enables a sandbox for the requested resource.", Color: ""},
	"disown-opener":               {Desc: "Ensures a resource will disown its opener when navigated to.", Color: ""},
	"form-action":                 {Desc: "Restricts the URLs which can be used as the target of a form submissions.", Color: ""},
	"frame-ancestors":             {Desc: "Specifies valid parents that may embed a page.", Color: ""},
	"navigate-to":                 {Desc: "Restricts the URLs to which a document can navigate.", Color: ""},
	"report-uri":                  {Desc: "Instructs the user agent to report attempts to violate the CSP.", Color: ""},
	"report-to":                   {Desc: "Fires a SecurityPolicyViolationEvent.", Color: ""},
	"block-all-mixed-content":     {Desc: "Prevents loading any assets using HTTP when the page is loaded using HTTPS.", Color: ""},
	"referrer":                    {Desc: "Used to specify information in the referer header.", Color: ""},
	"require-sri-for":             {Desc: "Requires the use of SRI for scripts or styles.", Color: ""},
	"upgrade-insecure-requests":   {Desc: "Instructs user agents to treat all of a site's insecure URLs as secure.", Color: ""},
	"*":                           {Desc: "Wildcard, allows any URL except data: blob: filesystem: schemes.", Color: ColorRed},
	"'none'":                      {Desc: "Prevents loading resources from any source.", Color: ColorGreen},
	"'self'":                      {Desc: "Allows loading resources from the same origin.", Color: ColorGreen},
	"data:":                       {Desc: "Allows loading resources via the data scheme.", Color: ColorYellow},
	"blob:":                       {Desc: "Allows loading resources via the blob scheme.", Color: ColorYellow},
	"https:":                      {Desc: "Allows loading resources only over HTTPS on any domain.", Color: ColorGreen},
	"'unsafe-inline'":             {Desc: "Allows use of inline source elements.", Color: ColorRed},
	"'unsafe-eval'":               {Desc: "Allows unsafe dynamic code evaluation.", Color: ColorRed},
	"'nonce-'":                    {Desc: "Allows script or style tag to execute if the nonce attribute value matches.", Color: ColorGreen},
	"'sha256-'":                   {Desc: "Allow a specific script or style to execute if it matches the hash.", Color: ColorGreen},
}

var warningLevels = map[int]string{
	0: ColorWhite,
	1: ColorCyan,
	2: ColorGreen,
	3: ColorYellow,
	4: ColorDarkOrange,
	5: ColorRed,
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
}

type Result struct {
	URL     string `json:"url"`
	Status  string `json:"status"`
	Details string `json:"details"`
	Error   string `json:"error,omitempty"`
}

func main() {
	filePath := flag.String("f", "", "File containing list of domains (domains.txt)")
	targetURL := flag.String("t", "", "Single target URL")
	concurrency := flag.Int("c", 20, "Number of concurrent threads")
	outputFile := flag.String("o", "", "Output file path (optional)")
	proxyURL := flag.String("proxy", "", "Proxy URL (e.g., http://127.0.0.1:8080)")
	timeoutSec := flag.Int("timeout", 10, "Request timeout in seconds")
	baseUserAgent := flag.String("ua", "RedTeam-Clickjack-Scanner/1.0", "Custom User-Agent")
	cspAnalyzer := flag.Bool("csp-analyzer", false, "Analyze CSP headers (requires -t)")
	stealth := flag.Bool("stealth", false, "Enable Stealth Mode (Random User-Agent, Jitter)")
	jsonOutput := flag.Bool("json", false, "Output results in JSON format")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	rand.Seed(time.Now().UnixNano())

	if *cspAnalyzer {
		if *targetURL == "" {
			fmt.Println("Error: -csp-analyzer requires -t <url>")
			return
		}
		analyzeCSP(*targetURL, *proxyURL, *timeoutSec, *baseUserAgent)
		return
	}

	if *filePath == "" && *targetURL == "" {
		flag.Usage()
		return
	}

	var domains []string
	if *filePath != "" {
		d, err := readLines(*filePath)
		if err != nil {
			fmt.Printf("Error reading file: %v\n", err)
			return
		}
		domains = append(domains, d...)
	}
	if *targetURL != "" {
		domains = append(domains, *targetURL)
	}

	var parsedProxy *url.URL
	var err error
	if *proxyURL != "" {
		parsedProxy, err = url.Parse(*proxyURL)
		if err != nil {
			fmt.Printf("Invalid proxy URL: %v\n", err)
			return
		}
	}

	jobs := make(chan string, len(domains))
	results := make(chan Result, len(domains))
	var wg sync.WaitGroup

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg, parsedProxy, *timeoutSec, *baseUserAgent, *stealth)
	}

	for _, domain := range domains {
		jobs <- domain
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var f *os.File
	if *outputFile != "" {
		f, err = os.Create(*outputFile)
		if err != nil {
			fmt.Printf("Error creating output file: %v\n", err)
			return
		}
		defer f.Close()
	}

	var jsonResults []Result

	for res := range results {
		if *jsonOutput {
			jsonResults = append(jsonResults, res)
			continue
		}

		if res.Status == "Vulnerable" {
			msg := fmt.Sprintf("[+] Vulnerable: %s (%s)", res.URL, res.Status)
			fmt.Println(msg)
			if f != nil {
				f.WriteString(msg + "\n")
			}
		} else if res.Status == "Potentially Vulnerable" {
			msg := fmt.Sprintf("[?] Potentially Vulnerable: %s (%s)", res.URL, res.Details)
			fmt.Println(msg)
			if f != nil {
				f.WriteString(msg + "\n")
			}
		}
	}

	if *jsonOutput {
		Encoder := json.NewEncoder(os.Stdout)
		Encoder.SetIndent("", "  ")
		Encoder.Encode(jsonResults)
		if f != nil {
			fEncoder := json.NewEncoder(f)
			fEncoder.SetIndent("", "  ")
			fEncoder.Encode(jsonResults)
		}
	}
}

func analyzeCSP(targetURL string, proxyURL string, timeoutSec int, userAgent string) {
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "https://" + targetURL
	}

	fmt.Printf("Calling %s...\n\n", targetURL)

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		fmt.Printf("Error parsing URL: %v\n", err)
		return
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if proxyURL != "" {
		pURL, _ := url.Parse(proxyURL)
		transport.Proxy = http.ProxyURL(pURL)
	}

	client := &http.Client{
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Transport: transport,
	}

	req, _ := http.NewRequest("GET", targetURL, nil)
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error connecting: %v\n", err)
		return
	}
	defer resp.Body.Close()

	cspHeader := resp.Header.Get("Content-Security-Policy")
	if cspHeader == "" {
		fmt.Println("Content-Security-Policy not found!")
		return
	}

	directives := strings.Split(cspHeader, ";")
	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if directive == "" {
			continue
		}

		parts := strings.Split(directive, " ")
		policyName := parts[0]

		fmt.Printf("%s%s%s%s", ColorCyan, ColorReverse, policyName, ColorReset)
		if info, ok := cspHelp[policyName]; ok {
			fmt.Printf(" %s[%s]%s", ColorWhite, info.Desc, ColorReset)
		}
		fmt.Println()

		for i := 1; i < len(parts); i++ {
			val := strings.TrimSpace(parts[i])
			if val == "" {
				continue
			}

			origVal := val
			checkVal := val
			if strings.HasPrefix(val, "'nonce-") {
				checkVal = "'nonce-'"
			} else if strings.HasPrefix(val, "'sha256-") {
				checkVal = "'sha256-'"
			}

			var color string
			if info, ok := cspHelp[checkVal]; ok && info.Color != "" {
				color = info.Color
			} else {
				wLevel := getWarningLevel(parsedURL, val)
				color = warningLevels[wLevel]
			}

			fmt.Printf(" %s+ %s%s", color, ColorReset, origVal)
			if info, ok := cspHelp[checkVal]; ok && info.Desc != "" {
				fmt.Printf(" %s[%s]%s", color, info.Desc, ColorReset)
			}
			fmt.Println()
		}
		fmt.Println()
	}
}

func getWarningLevel(mainURL *url.URL, item string) int {
	if _, ok := cspHelp[item]; ok {
		return 0
	}

	if !strings.HasPrefix(item, "http") && !strings.HasPrefix(item, "data:") && !strings.HasPrefix(item, "blob:") {
	}

	wLevel := 4

	wildcardOffset := 0
	if strings.Contains(item, "*") {
		wildcardOffset = 1
		item = strings.ReplaceAll(item, "*", "wildcard")
	}

	targetHost := mainURL.Host

	var itemHost string
	if strings.HasPrefix(item, "http") || strings.HasPrefix(item, "//") {
		u, err := url.Parse(item)
		if err == nil {
			itemHost = u.Host
		}
	} else {
		if idx := strings.Index(item, "/"); idx != -1 {
			itemHost = item[:idx]
		} else {
			itemHost = item
		}
	}

	if itemHost == "" {
		return 4 + wildcardOffset
	}

	if itemHost == targetHost {
		wLevel = 1
	} else if strings.HasSuffix(targetHost, "."+itemHost) || strings.HasSuffix(itemHost, "."+targetHost) {
		wLevel = 2
	} else {
		partsMain := strings.Split(targetHost, ".")
		partsItem := strings.Split(itemHost, ".")
		if len(partsMain) > 1 && len(partsItem) > 1 {
			baseMain := partsMain[len(partsMain)-2] + "." + partsMain[len(partsMain)-1]
			baseItem := partsItem[len(partsItem)-2] + "." + partsItem[len(partsItem)-1]
			if baseMain == baseItem {
				wLevel = 3
			}
		}
	}

	finalLevel := wLevel + wildcardOffset
	if finalLevel > 5 {
		finalLevel = 5
	}
	return finalLevel
}

func worker(jobs <-chan string, results chan<- Result, wg *sync.WaitGroup, proxy *url.URL, timeout int, baseUserAgent string, stealth bool) {
	defer wg.Done()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if proxy != nil {
		transport.Proxy = http.ProxyURL(proxy)
	}

	client := &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: transport,
	}

	for targetURL := range jobs {
		if !strings.HasPrefix(targetURL, "http") {
			targetURL = "http://" + targetURL
		}

		if stealth {
			time.Sleep(time.Duration(rand.Intn(2000)) * time.Millisecond)
		}

		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			results <- Result{URL: targetURL, Error: err.Error()}
			continue
		}

		ua := baseUserAgent
		if stealth {
			ua = userAgents[rand.Intn(len(userAgents))]
		}
		req.Header.Set("User-Agent", ua)

		resp, err := client.Do(req)
		if err != nil {
			results <- Result{URL: targetURL, Error: err.Error()}
			continue
		}

		xframes := resp.Header.Get("X-Frame-Options")
		csp := resp.Header.Get("Content-Security-Policy")

		isSecure := false
		details := []string{}

		if xframes != "" {
			if strings.EqualFold(xframes, "DENY") || strings.EqualFold(xframes, "SAMEORIGIN") {
				isSecure = true
			}
			details = append(details, fmt.Sprintf("XFO: %s", xframes))
		} else {
			details = append(details, "XFO: Missing")
		}

		if strings.Contains(csp, "frame-ancestors") {
			isSecure = true
		}
		if csp != "" {
			details = append(details, "CSP: Present")
		} else {
			details = append(details, "CSP: Missing")
		}

		if !isSecure {
			bodyBytes, _ := io.ReadAll(resp.Body)
			bodyString := string(bodyBytes)

			frameBustingPatterns := []string{
				"top.location",
				"window.top",
				"top.location.hostname",
				"top.location.replace",
				"top != self",
				"top!=self",
				"if (top",
			}

			foundFrameBusting := false
			for _, pattern := range frameBustingPatterns {
				if strings.Contains(bodyString, pattern) {
					foundFrameBusting = true
					break
				}
			}

			if foundFrameBusting {
				results <- Result{
					URL:     targetURL,
					Status:  "Potentially Vulnerable",
					Details: "Frame Busting Detected (Headers Missing)",
				}
			} else {
				results <- Result{
					URL:     targetURL,
					Status:  "Vulnerable",
					Details: strings.Join(details, ", "),
				}
			}
		} else {
			results <- Result{
				URL:     targetURL,
				Status:  "Secure",
				Details: strings.Join(details, ", "),
			}
		}
		resp.Body.Close()
	}
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}
