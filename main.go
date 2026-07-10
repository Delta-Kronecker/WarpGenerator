package main

import (
	"archive/zip"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

const (
	RED    = "1"
	GREEN  = "2"
	ORANGE = "208"
	BLUE   = "39"
)

var (
	ipv4Prefixes = []string{
		"188.114.96.", "188.114.97.", "188.114.98.", "188.114.99.",
		"162.159.192.", "162.159.193.", "162.159.195.", "8.34.146.",
		"8.39.214.", "8.39.204.", "8.6.112.", "8.35.211.", "8.39.125.",
		"8.47.69.",
	}
	ports = []int{
		500, 854, 859, 864, 878, 880, 890, 891, 894, 903,
		908, 928, 934, 939, 942, 943, 945, 946, 955, 968,
		987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387,
		1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177,
		4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
	}
)

type ScanConfig struct {
	IPv4Retries          int
	RetryStaggeringMs    int
	EndpointStaggeringMs int
	RangeRetries         int
	MaxConcurrent        int
	UseNoise             bool
	UdpNoise             Noise
	Endpoints            []string
	SelectedPrefixes     []string
}

var (
	VERSION  = "dev"
	prompt   = fmtStr("●", GREEN, true)
	errMark  = fmtStr("✗", RED, true)
	succMark = fmtStr("✓", GREEN, true)
	xrayPath string
)

var scanConfig = ScanConfig{
	UseNoise: true,
	UdpNoise: Noise{
		Type:   "rand",
		Packet: "50-100",
		Delay:  "1-5",
		Count:  5,
	},
	IPv4Retries:          3,
	RetryStaggeringMs:    200,
	EndpointStaggeringMs: 100,
}

type ScanResult struct {
	Endpoint string
	Loss     float64
	Latency  int64
}

func fmtStr(str string, color string, isBold bool) string {
	style := lipgloss.NewStyle().Bold(isBold)

	if color != "" {
		style = style.Foreground(lipgloss.Color(color))
	}

	return style.Render(str)
}

func failMessage(message string) {
	fmt.Printf("%s %s\n", errMark, message)
}

func successMessage(message string) {
	fmt.Printf("\n%s %s\n", succMark, message)
}

func generateEndpoints() {
	endpoints := make([]string, 0)
	seen := make(map[string]bool)

	for _, prefix := range scanConfig.SelectedPrefixes {
		for i := 0; i < 256; i++ {
			ip := fmt.Sprintf("%s%d", prefix, i)
			for _, port := range ports {
				endpoint := fmt.Sprintf("%s:%d", ip, port)
				if !seen[endpoint] {
					seen[endpoint] = true
					endpoints = append(endpoints, endpoint)
				}
			}
		}
	}

	message := fmt.Sprintf("Generated %d endpoints to test", len(endpoints))
	successMessage(message)
	scanConfig.Endpoints = endpoints
}

func must[T any](v T, _ error) T { return v }

func writeLines(path string, lines []string) error {
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
}

func generateWarpConfig() error {
	wgcfPath := "./wgcf"
	if runtime.GOOS == "windows" {
		wgcfPath = "./wgcf.exe"
	}

	if _, err := os.Stat(wgcfPath); err != nil {
		return fmt.Errorf("wgcf not found at %s", wgcfPath)
	}

	maxRetries := 10
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		fmt.Printf("\n=== Registering WARP account (attempt %d/%d) ===\n", attempt, maxRetries)
		cmd := exec.Command(wgcfPath, "register")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			lastErr = err
			fmt.Printf("Attempt %d/%d failed: %v\n", attempt, maxRetries, err)
			time.Sleep(3 * time.Second)
			continue
		}
		fmt.Println("=== WARP account registered ===")
		lastErr = nil
		break
	}

	if lastErr != nil {
		return fmt.Errorf("wgcf register failed after %d attempts: %v", maxRetries, lastErr)
	}

	fmt.Println("\n=== Generating WireGuard profile ===")
	cmd := exec.Command(wgcfPath, "generate")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wgcf generate failed: %v", err)
	}
	fmt.Println("=== WireGuard profile generated: wgcf-profile.conf ===")

	return nil
}

type WireGuardConfig struct {
	PrivateKey string
	PublicKey  string
	Address    string
	MTU        string
}

func parseWgConfig(conf string) WireGuardConfig {
	cfg := WireGuardConfig{MTU: "1280"}
	lines := strings.Split(conf, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PrivateKey") {
			cfg.PrivateKey = strings.TrimSpace(strings.SplitN(line, "=", 2)[1])
		} else if strings.HasPrefix(line, "Address") {
			cfg.Address = strings.TrimSpace(strings.SplitN(line, "=", 2)[1])
		} else if strings.HasPrefix(line, "PublicKey") {
			cfg.PublicKey = strings.TrimSpace(strings.SplitN(line, "=", 2)[1])
		} else if strings.HasPrefix(line, "MTU") {
			cfg.MTU = strings.TrimSpace(strings.SplitN(line, "=", 2)[1])
		}
	}
	return cfg
}

func generateWireGuardURI(cfg WireGuardConfig, endpoint string) string {
	addr := strings.Split(cfg.Address, ",")[0]
	addr = strings.ReplaceAll(addr, " ", "")
	pubKey := url.QueryEscape(cfg.PublicKey)
	privKey := url.QueryEscape(cfg.PrivateKey)
	return fmt.Sprintf("wireguard://%s@%s?publickey=%s&address=%s&mtu=%s", privKey, endpoint, pubKey, addr, cfg.MTU)
}

func generateClashConfig(results []ScanResult, wgCfg WireGuardConfig) {
	var yaml strings.Builder

	yaml.WriteString("name: \"Standard\"\n")
	yaml.WriteString("mixed-port: 7890\n")
	yaml.WriteString("socks-port: 7891\n")
	yaml.WriteString("port: 7892\n")
	yaml.WriteString("allow-lan: true\n")
	yaml.WriteString("bind-address: '*'\n")
	yaml.WriteString("mode: global\n")
	yaml.WriteString("log-level: info\n")
	yaml.WriteString("ipv6: false\n")
	yaml.WriteString("external-controller: 127.0.0.1:9090\n")
	yaml.WriteString("external-ui: ui\n")
	yaml.WriteString("secret: \"\"\n")
	yaml.WriteString("unified-delay: true\n")
	yaml.WriteString("tcp-concurrent: true\n")
	yaml.WriteString("global-client-fingerprint: chrome\n")
	yaml.WriteString("find-process-mode: strict\n")
	yaml.WriteString("keep-alive-interval: 15\n\n")

	yaml.WriteString("profile:\n")
	yaml.WriteString("  store-selected: true\n")
	yaml.WriteString("  store-fake-ip: false\n\n")

	yaml.WriteString("dns:\n")
	yaml.WriteString("  enable: true\n")
	yaml.WriteString("  ipv6: false\n")
	yaml.WriteString("  listen: 0.0.0.0:5353\n")
	yaml.WriteString("  enhanced-mode: fake-ip\n")
	yaml.WriteString("  fake-ip-range: 198.18.0.1/16\n")
	yaml.WriteString("  fake-ip-filter:\n")
	yaml.WriteString("    - '*.local'\n")
	yaml.WriteString("    - '*.lan'\n")
	yaml.WriteString("    - '*.localhost'\n")
	yaml.WriteString("    - '+.stun.*.*'\n")
	yaml.WriteString("    - '+.stun.*.*.*'\n")
	yaml.WriteString("    - 'time.*'\n")
	yaml.WriteString("    - 'time.*.com'\n")
	yaml.WriteString("    - 'connectivitycheck.gstatic.com'\n")
	yaml.WriteString("    - 'detectportal.firefox.com'\n")
	yaml.WriteString("    - 'captive.apple.com'\n")
	yaml.WriteString("    - 'www.msftncsi.com'\n")
	yaml.WriteString("    - 'cp.cloudflare.com'\n")
	yaml.WriteString("  default-nameserver:\n")
	yaml.WriteString("    - 1.1.1.1\n")
	yaml.WriteString("    - 1.0.0.1\n")
	yaml.WriteString("    - 8.8.8.8\n")
	yaml.WriteString("    - 8.8.4.4\n")
	yaml.WriteString("    - 9.9.9.9\n")
	yaml.WriteString("    - 149.112.112.112\n")
	yaml.WriteString("    - 208.67.222.222\n")
	yaml.WriteString("    - 208.67.220.220\n")
	yaml.WriteString("    - 94.140.14.14\n")
	yaml.WriteString("    - 94.140.15.15\n")
	yaml.WriteString("    - 64.6.64.6\n")
	yaml.WriteString("    - 64.6.65.6\n")
	yaml.WriteString("    - 84.200.69.80\n")
	yaml.WriteString("    - 84.200.70.40\n")
	yaml.WriteString("    - 76.76.19.19\n")
	yaml.WriteString("    - 76.223.122.150\n")
	yaml.WriteString("    - 8.26.56.26\n")
	yaml.WriteString("    - 8.20.247.20\n")
	yaml.WriteString("  nameserver:\n")
	yaml.WriteString("    - https://cloudflare-dns.com/dns-query\n")
	yaml.WriteString("    - https://1.1.1.1/dns-query\n")
	yaml.WriteString("    - https://1.0.0.1/dns-query\n")
	yaml.WriteString("    - https://dns.google/dns-query\n")
	yaml.WriteString("    - https://8.8.8.8/dns-query\n")
	yaml.WriteString("    - https://8.8.4.4/dns-query\n")
	yaml.WriteString("    - https://dns.quad9.net/dns-query\n")
	yaml.WriteString("    - https://9.9.9.9/dns-query\n")
	yaml.WriteString("    - https://149.112.112.112/dns-query\n")
	yaml.WriteString("    - https://dns.adguard.com/dns-query\n")
	yaml.WriteString("    - https://94.140.14.14/dns-query\n")
	yaml.WriteString("    - https://94.140.15.15/dns-query\n")
	yaml.WriteString("    - https://doh.opendns.com/dns-query\n")
	yaml.WriteString("    - https://208.67.222.222/dns-query\n")
	yaml.WriteString("    - https://208.67.220.220/dns-query\n")
	yaml.WriteString("    - https://doh.comodo.com/dns-query\n")
	yaml.WriteString("    - https://8.26.56.26/dns-query\n")
	yaml.WriteString("    - https://8.20.247.20/dns-query\n")
	yaml.WriteString("    - https://doh.mullvad.net/dns-query\n")
	yaml.WriteString("    - https://doh.dns.mullvad.net/dns-query\n")
	yaml.WriteString("    - https://freedns.controld.com/p0\n")
	yaml.WriteString("    - https://freedns.controld.com/family\n\n")

	yaml.WriteString("proxies:\n")
	for i, r := range results {
		parts := strings.SplitN(r.Endpoint, ":", 2)
		server := parts[0]
		port := parts[1]
		name := fmt.Sprintf("Warp-%d", i+1)

		yaml.WriteString(fmt.Sprintf("  - name: \"%s\"\n", name))
		yaml.WriteString("    type: wireguard\n")
		yaml.WriteString(fmt.Sprintf("    private-key: \"%s\"\n", wgCfg.PrivateKey))
		yaml.WriteString(fmt.Sprintf("    public-key: \"%s\"\n", wgCfg.PublicKey))
		yaml.WriteString("    ip: \"172.16.0.2\"\n")
		yaml.WriteString("    server: " + server + "\n")
		yaml.WriteString("    port: " + port + "\n")
		yaml.WriteString("    reserved: [0, 0, 0]\n")
		yaml.WriteString("    mtu: " + wgCfg.MTU + "\n")
		yaml.WriteString("    udp: true\n\n")
	}

	yaml.WriteString("proxy-groups:\n")
	yaml.WriteString("  - name: \"PROXY\"\n")
	yaml.WriteString("    type: select\n")
	yaml.WriteString("    proxies:\n")
	yaml.WriteString("      - \"Auto\"\n\n")

	yaml.WriteString("  - name: \"Auto\"\n")
	yaml.WriteString("    type: url-test\n")
	yaml.WriteString("    url: http://www.gstatic.com/generate_204\n")
	yaml.WriteString("    interval: 60\n")
	yaml.WriteString("    tolerance: 10\n")
	yaml.WriteString("    lazy: true\n")
	yaml.WriteString("    proxies:\n")
	for i := range results {
		yaml.WriteString(fmt.Sprintf("      - \"Warp-%d\"\n", i+1))
	}

	yaml.WriteString("\nrules:\n")
	yaml.WriteString("  - MATCH,PROXY\n")

	if err := os.WriteFile("clash_config.yaml", []byte(yaml.String()), 0644); err == nil {
		successMessage(fmt.Sprintf("Generated Clash config: clash_config.yaml"))
	}
}

func generateConfigsZip(results []ScanResult) {
	confFile, err := os.ReadFile("wgcf-profile.conf")
	if err != nil {
		failMessage(fmt.Sprintf("Cannot read wgcf-profile.conf: %v", err))
		return
	}

	conf := string(confFile)
	wgCfg := parseWgConfig(conf)

	zipFile, err := os.Create("warp_configs.zip")
	if err != nil {
		failMessage(fmt.Sprintf("Cannot create zip file: %v", err))
		return
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	var uris []string

	for i, r := range results {
		config := strings.Replace(conf, "engage.cloudflareclient.com:2408", r.Endpoint, 1)
		configName := fmt.Sprintf("warp_%d_%s.conf", i+1, strings.Replace(r.Endpoint, ":", "_", -1))

		entry, err := zipWriter.Create(configName)
		if err != nil {
			continue
		}
		entry.Write([]byte(config))

		uris = append(uris, generateWireGuardURI(wgCfg, r.Endpoint))
	}

	zipWriter.Close()
	zipFile.Close()

	uriContent := strings.Join(uris, "\n")
	if err := os.WriteFile("warp_links.txt", []byte(uriContent), 0644); err == nil {
		successMessage(fmt.Sprintf("Generated %d URI links in warp_links.txt", len(results)))
	}

	generateClashConfig(results, wgCfg)

	successMessage(fmt.Sprintf("Generated %d configs in warp_configs.zip", len(results)))
}

func renderEndpoints(results []ScanResult) {
	message := fmt.Sprintf("Found %d working endpoints:\n", len(results))
	successMessage(message)

	var tableRows [][]string
	for _, r := range results {
		tableRows = append(tableRows, []string{
			r.Endpoint,
			fmt.Sprintf("%.1f %%", r.Loss),
			fmt.Sprintf("%d ms", r.Latency),
		})
	}

	t := table.New().
		Border(lipgloss.MarkdownBorder()).
		BorderTop(true).
		BorderBottom(true).
		BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color(GREEN))).
		StyleFunc(func(row, col int) lipgloss.Style {
			style := lipgloss.NewStyle().Padding(0, 2).Align(lipgloss.Center)
			if row == table.HeaderRow {
				style = style.Bold(true)
				if col == 0 {
					style = style.Foreground(lipgloss.Color(GREEN))
				} else {
					style = style.Foreground(lipgloss.Color(ORANGE))
				}
			}
			return style
		}).
		Headers("Endpoint", "Loss rate", "Latency").
		Rows(tableRows...)
	fmt.Println(t.Render())
}

func checkNum(num string, min int, max int) (bool, int) {
	n, err := strconv.Atoi(num)
	if err != nil {
		return false, 0
	} else if n < min || n > max {
		return false, 0
	} else {
		return true, n
	}
}

func isValidHex(value string) bool {
	matched, err := regexp.MatchString(`^[0-9a-fA-F]+$`, value)
	if err != nil {
		return false
	}

	return len(value) > 0 && matched
}

func isValidBase64(value string) bool {
	if len(value) == 0 {
		return false
	}

	_, err := base64.StdEncoding.DecodeString(value)
	return err == nil
}

func isValidRange(value string) bool {
	if value == "" {
		return false
	}

	regex := `^(?:[1-9][0-9]*|[1-9][0-9]*-[1-9][0-9]*)$`
	matched, err := regexp.MatchString(regex, value)
	if err != nil {
		return false
	}

	split := strings.Split(value, "-")
	if len(split) == 2 {
		min, _ := strconv.Atoi(split[0])
		max, _ := strconv.Atoi(split[1])
		return max >= min
	}

	return matched
}

func init() {
	showVersion := flag.Bool("version", false, "Show version")
	flag.Parse()

	if *showVersion {
		fmt.Println(VERSION)
		os.Exit(0)
	}

	logDir := filepath.Join("core", "log")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		failMessage("Failed to create Xray log directory")
		log.Fatal(err)
	}

	accessLog := filepath.Join(logDir, "access.log")
	errorLog := filepath.Join(logDir, "error.log")
	for _, file := range []string{accessLog, errorLog} {
		file, err := os.Create(file)
		if err != nil {
			failMessage("Failed to create Xray log file")
			log.Fatal(err)
		}
		defer file.Close()
	}

	var binary string
	if runtime.GOOS == "windows" {
		binary = "xray.exe"
	} else {
		binary = "xray"
	}
	xrayPath = filepath.Join("core", binary)

	if _, err := os.Stat(xrayPath); err != nil {
		failMessage("Xray core not found.")
		log.Fatal(err)
	}

	err := os.Chmod(xrayPath, 0755)
	if err != nil {
		failMessage("Failed to set Xray core permissions.")
		log.Fatal(err)
	}

	path := os.Getenv("PATH")
	if runtime.GOOS == "android" || strings.Contains(path, "com.termux") {
		prefix := os.Getenv("PREFIX")
		certPath := filepath.Join(prefix, "etc/tls/cert.pem")
		if err := os.Setenv("SSL_CERT_FILE", certPath); err != nil {
			failMessage("Failed to set Termux cert file.")
			log.Fatalln(err)
		}
	}
}

func main() {
	fmt.Printf("\n%s Available IPv4 Prefixes:", fmtStr("Select ranges to scan:", BLUE, true))
	for i, prefix := range ipv4Prefixes {
		fmt.Printf("\n   %s %s", fmtStr(fmt.Sprintf("%d.", i+1), GREEN, false), prefix)
	}

	fmt.Printf("\n\n%s You can select multiple (e.g., 1,3,5 or 1-5 or all)", fmtStr("Tip:", ORANGE, false))

	for {
		fmt.Printf("\n\n%s Enter range numbers to scan (or 'all') [11]: ", prompt)
		var input string
		fmt.Scanln(&input)

		if input == "" {
			input = "11"
		}

		if input == "all" || input == "ALL" {
			scanConfig.SelectedPrefixes = make([]string, len(ipv4Prefixes))
			copy(scanConfig.SelectedPrefixes, ipv4Prefixes)
			break
		}

		selected := make(map[int]bool)
		parts := strings.Split(input, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.Contains(part, "-") {
				rangeParts := strings.Split(part, "-")
				if len(rangeParts) == 2 {
					start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
					end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
					if err1 == nil && err2 == nil && start >= 1 && end <= len(ipv4Prefixes) && start <= end {
						for i := start; i <= end; i++ {
							selected[i] = true
						}
					}
				}
			} else {
				num, err := strconv.Atoi(part)
				if err == nil && num >= 1 && num <= len(ipv4Prefixes) {
					selected[num] = true
				}
			}
		}

		if len(selected) == 0 {
			failMessage("Invalid input. Please try again.")
			continue
		}

		for num := range selected {
			scanConfig.SelectedPrefixes = append(scanConfig.SelectedPrefixes, ipv4Prefixes[num-1])
		}
		break
	}

	fmt.Printf("\n%s Test with noise", fmtStr("1.", BLUE, true))
	fmt.Printf("\n%s Test with no noise", fmtStr("2.", BLUE, true))
	for {
		var res string
		fmt.Printf("\n%s Please select (1 or 2) [1]: ", prompt)
		fmt.Scanln(&res)
		if res == "" {
			res = "1"
		}
		switch res {
		case "1":
		case "2":
			scanConfig.UseNoise = false
		default:
			failMessage("Invalid choice. Please select 1 or 2.")
			continue
		}
		break
	}

	if scanConfig.UseNoise {
		fmt.Printf("\n%s Use default noise", fmtStr("1.", BLUE, true))
		fmt.Printf("\n%s Setup custom noise", fmtStr("2.", BLUE, true))
		for {
			var res string
			fmt.Printf("\n%s Please select (1 or 2) [1]: ", prompt)
			fmt.Scanln(&res)
			if res == "" {
				res = "1"
			}
			switch res {
			case "1":
			case "2":
				fmt.Printf("\n%s Base64", fmtStr("1.", BLUE, true))
				fmt.Printf("\n%s Hex", fmtStr("2.", BLUE, true))
				fmt.Printf("\n%s String", fmtStr("3.", BLUE, true))
				fmt.Printf("\n%s Random", fmtStr("4.", BLUE, true))
				var noiseType, packet, delay, count string
				for {
					var res string
					fmt.Printf("\n\n%s Please select UDP noise type (1-4): ", prompt)
					fmt.Scanln(&res)
					switch res {
					case "1":
						noiseType = "base64"
					case "2":
						noiseType = "hex"
					case "3":
						noiseType = "str"
					case "4":
					noiseType = "rand"
				default:
					failMessage("Invalid choice. Please select 1-4.")
					continue
				}
				break
			}

			for {
				fmt.Printf("\n%s Please enter a %s packet: ", prompt, fmtStr(noiseType, GREEN, true))
				fmt.Scanln(&packet)
				switch noiseType {
				case "base64":
					if !isValidBase64(packet) {
						msg := fmt.Sprintf("Invalid packet for Base64 type, please enter a valid Base64 value like %s.", fmtStr("aGVsbG8gd29ybGQ=", GREEN, true))
						failMessage(msg)
						continue
					}
				case "hex":
					if !isValidHex(packet) {
						msg := fmt.Sprintf("Invalid packet for Hex type, please enter a valid Hex value like %s.", fmtStr("68656c6c6f20776f726c64", GREEN, true))
						failMessage(msg)
						continue
					}
				case "rand":
					if !isValidRange(packet) {
						msg := fmt.Sprintf("Invalid packet for Random type, please enter packet length, it can be a fixed number or an interval like %s.", fmtStr("50-100", GREEN, true))
						failMessage(msg)
						continue
					}
				}
				break
			}

			for {
				fmt.Printf("\n%s Please enter noise delay in miliseconds, it can be a fixed number or an interval like %s: ", prompt, fmtStr("1-5", GREEN, true))
				fmt.Scanln(&delay)
				if !isValidRange(delay) {
					failMessage("Invalid delay value, please try again.")
					continue
				}
				break
			}

			for {
				fmt.Printf("\n%s Please enter number of noise packets (up to 50): ", prompt)
				fmt.Scanln(&count)
				isValid, noiseCount := checkNum(count, 1, 50)
				if !isValid {
					failMessage("Invalid value. Please enter a numeric value between 1 and 50.")
					continue
				}
				scanConfig.UdpNoise = Noise{
					Type:   noiseType,
					Packet: packet,
					Delay:  delay,
					Count:  noiseCount,
				}
				break
			}

		default:
			failMessage("Invalid choice. Please select 1 or 2.")
			continue
		}
		break
		}
	}

	for {
		fmt.Printf("\n%s How many times to retry failed endpoints (0-10) [0]: ", prompt)
		var retriesStr string
		fmt.Scanln(&retriesStr)
		if retriesStr == "" {
			scanConfig.RangeRetries = 0
			break
		}
		isValid, retries := checkNum(retriesStr, 0, 10)
		if !isValid {
			failMessage("Invalid input. Please enter a number between 0-10.")
			continue
		}
		scanConfig.RangeRetries = retries
		break
	}

	for {
		fmt.Printf("\n%s How many endpoints to test concurrently (10-200) [50]: ", prompt)
		var concurrentStr string
		fmt.Scanln(&concurrentStr)
		if concurrentStr == "" {
			scanConfig.MaxConcurrent = 50
			break
		}
		isValid, concurrent := checkNum(concurrentStr, 10, 200)
		if !isValid {
			failMessage("Invalid input. Please enter a number between 10-200.")
			continue
		}
		scanConfig.MaxConcurrent = concurrent
		break
	}

	checkNetworkStats(false)
	generateEndpoints()

	go listenForStop()

	fmt.Printf("\n%s Press Ctrl+S to stop scan and save results\n", prompt)

	results, err := scanEndpoints()
	if err != nil {
		failMessage("Scan failed.")
		log.Fatal(err)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Latency < results[j].Latency
	})

	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
	} else {
		if err := os.WriteFile("result.json", jsonData, 0644); err != nil {
			fmt.Printf("Error saving results: %v\n", err)
		}
	}

	renderEndpoints(results)
	successMessage("Scan completed.")
	message := fmt.Sprintf("Found %d endpoints. You can check result.json for more details.\n", len(results))
	successMessage(message)

	fmt.Printf("\n%s Do you want to generate WARP config with wgcf? (y/n) [y]: ", prompt)
	var choice string
	fmt.Scanln(&choice)
	if choice == "" || choice == "y" || choice == "Y" {
		if err := generateWarpConfig(); err != nil {
			failMessage(fmt.Sprintf("Failed to generate WARP config: %v", err))
	} else {
		successMessage("WARP config generated: wgcf-profile.conf")
	}

	generateConfigsZip(results)
}

	fmt.Printf("\n%s Press Enter to exit...", prompt)
	fmt.Scanln()
}
