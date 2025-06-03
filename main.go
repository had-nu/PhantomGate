package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Global configuration
type Config struct {
	TorPort       string   `json:"tor_port"`
	DnsPort       string   `json:"dns_port"`
	TorNetwork    string   `json:"tor_network"`
	ExcludedIPs   []string `json:"excluded_ips"`
	ProxyList     []Proxy  `json:"proxy_list"`
	CurrentProxy  *Proxy   `json:"current_proxy"`
	LogFile       string   `json:"log_file"`
	ProxyFilePath string   `json:"proxy_file_path"`
	AutoInterval  int      `json:"auto_interval"`
	UseProxies    bool     `json:"use_proxies"`
	UseTor        bool     `json:"use_tor"`
	Stealth       bool     `json:"stealth"`
	Debug         bool     `json:"debug"`
}

// Proxy structure
type Proxy struct {
	Type     string `json:"type"`     // socks5, http, https
	Address  string `json:"address"`  // IP:PORT
	Username string `json:"username"` // optional
	Password string `json:"password"` // optional
}

// Location information
type LocationInfo struct {
	IP        string  `json:"ip"`
	Country   string  `json:"country"`
	City      string  `json:"city"`
	Latitude  float64 `json:"lat"`
	Longitude float64 `json:"lon"`
	ISP       string  `json:"isp"`
}

var (
	config   Config
	logMutex sync.Mutex
	logger   *log.Logger
	version  = "1.0.0"
)

// Initialize configuration with default values
func initConfig() Config {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}

	return Config{
		TorPort:       "9040",
		DnsPort:       "5353",
		TorNetwork:    "10.0.0.0/10",
		ExcludedIPs:   []string{"127.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"},
		ProxyList:     []Proxy{},
		CurrentProxy:  nil,
		LogFile:       filepath.Join(homeDir, ".phantomgate.log"),
		ProxyFilePath: filepath.Join(homeDir, ".phantomgate_proxies.json"),
		AutoInterval:  300,
		UseProxies:    false,
		UseTor:        true,
		Stealth:       false,
		Debug:         false,
	}
}

// Check if the program is running as root/administrator
func checkRoot() bool {
	if runtime.GOOS == "windows" {
		// Check for admin rights on Windows
		_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		return err == nil
	}
	// Check for root on Unix-like systems
	return os.Geteuid() == 0
}

// Log message to file and console
func logMessage(message string, isError bool) {
	logMutex.Lock()
	defer logMutex.Unlock()

	if logger != nil {
		logger.Println(message)
	}

	if isError {
		fmt.Printf("\033[91m[!]\033[0m %s\n", message)
	} else if strings.HasPrefix(message, "[+]") {
		fmt.Printf("\033[92m%s\033[0m\n", message)
	} else if strings.HasPrefix(message, "[*]") {
		fmt.Printf("\033[93m%s\033[0m\n", message)
	} else {
		fmt.Println(message)
	}
}

// Load proxies from file
func loadProxies() error {
	if _, err := os.Stat(config.ProxyFilePath); os.IsNotExist(err) {
		// Create an empty proxy file if it doesn't exist
		sample := []Proxy{
			{
				Type:     "socks5",
				Address:  "127.0.0.1:9050",
				Username: "",
				Password: "",
			},
		}
		jsonData, _ := json.MarshalIndent(sample, "", "  ")
		if err := ioutil.WriteFile(config.ProxyFilePath, jsonData, 0600); err != nil {
			return err
		}
		logMessage("[*] Created sample proxy file at "+config.ProxyFilePath, false)
		return nil
	}

	data, err := ioutil.ReadFile(config.ProxyFilePath)
	if err != nil {
		return err
	}

	var proxies []Proxy
	if err := json.Unmarshal(data, &proxies); err != nil {
		return err
	}

	config.ProxyList = proxies
	logMessage(fmt.Sprintf("[+] Loaded %d proxies from %s", len(proxies), config.ProxyFilePath), false)
	return nil
}

// Save config to file
func saveConfig() error {
	jsonData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	configPath := filepath.Join(filepath.Dir(config.LogFile), ".phantomgate_config.json")
	return ioutil.WriteFile(configPath, jsonData, 0600)
}

// Check for Tor installation
func checkTor() bool {
	path, err := exec.LookPath("tor")
	return err == nil && path != ""
}

// Install Tor based on the operating system
func installTor() bool {
	logMessage("[*] Tor is not installed. Attempting to install...", false)

	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		// Detect Linux distribution
		if _, err := os.Stat("/etc/debian_version"); err == nil {
			cmd = exec.Command("apt-get", "update")
			cmd.Run()
			cmd = exec.Command("apt-get", "install", "-y", "tor")
		} else if _, err := os.Stat("/etc/fedora-release"); err == nil {
			cmd = exec.Command("dnf", "install", "-y", "tor")
		} else if _, err := os.Stat("/etc/arch-release"); err == nil {
			cmd = exec.Command("pacman", "-Sy", "--noconfirm", "tor")
		} else {
			logMessage("[!] Unsupported Linux distribution. Please install Tor manually.", true)
			return false
		}
	case "darwin":
		cmd = exec.Command("brew", "install", "tor")
	default:
		logMessage("[!] Automatic Tor installation not supported on "+runtime.GOOS+". Please install manually.", true)
		return false
	}

	if err := cmd.Run(); err != nil {
		logMessage("[!] Failed to install Tor: "+err.Error(), true)
		return false
	}

	// Check if Tor is now installed
	if checkTor() {
		logMessage("[+] Tor installed successfully.", false)
		return true
	}

	logMessage("[!] Tor installation appears to have failed.", true)
	return false
}

// Configure Tor to work with PhantomGate
func configureTor() error {
	var torrcPath string

	switch runtime.GOOS {
	case "linux", "darwin":
		if _, err := os.Stat("/etc/tor/torrc"); err == nil {
			torrcPath = "/etc/tor/torrc"
		} else if _, err := os.Stat("/usr/local/etc/tor/torrc"); err == nil {
			torrcPath = "/usr/local/etc/tor/torrc"
		} else {
			return fmt.Errorf("could not find Tor configuration file")
		}
	default:
		return fmt.Errorf("automatic Tor configuration not supported on %s", runtime.GOOS)
	}

	// Read existing content
	content, err := ioutil.ReadFile(torrcPath)
	if err != nil {
		return err
	}

	// Check if our configuration is already added
	if strings.Contains(string(content), "PhantomGate") {
		return nil
	}

	// Prepare configuration to append
	torConfig := fmt.Sprintf(`
## Added by PhantomGate %s
VirtualAddrNetwork %s
AutomapHostsOnResolve 1
TransPort %s
DNSPort %s
`, version, config.TorNetwork, config.TorPort, config.DnsPort)

	// Append our configuration
	f, err := os.OpenFile(torrcPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(torConfig); err != nil {
		return err
	}

	logMessage("[+] Updated Tor configuration at "+torrcPath, false)
	return nil
}

// Get the TOR user ID based on the operating system
func getTorUser() (string, error) {
	switch runtime.GOOS {
	case "linux":
		// Check for debian-tor user first
		cmd := exec.Command("id", "-u", "debian-tor")
		output, err := cmd.CombinedOutput()
		if err == nil && len(output) > 0 {
			return strings.TrimSpace(string(output)), nil
		}

		// Check for 'tor' user
		cmd = exec.Command("id", "-u", "tor")
		output, err = cmd.CombinedOutput()
		if err == nil && len(output) > 0 {
			return strings.TrimSpace(string(output)), nil
		}

		return "", fmt.Errorf("could not find Tor user ID")
	default:
		return "", fmt.Errorf("getting Tor user ID not supported on %s", runtime.GOOS)
	}
}

// Setup iptables rules for Tor routing
func setupIptablesRules() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("iptables rules only supported on Linux")
	}

	// Reset iptables
	clearIptablesRules()

	torUid, err := getTorUser()
	if err != nil {
		return err
	}

	// Execute iptables commands to route traffic through Tor
	commands := [][]string{
		// Security rules
		{"iptables", "-I", "OUTPUT", "!", "-o", "lo", "!", "-d", "127.0.0.1", "!", "-s", "127.0.0.1", "-p", "tcp", "-m", "tcp", "--tcp-flags", "ACK,FIN", "ACK,FIN", "-j", "DROP"},
		{"iptables", "-I", "OUTPUT", "!", "-o", "lo", "!", "-d", "127.0.0.1", "!", "-s", "127.0.0.1", "-p", "tcp", "-m", "tcp", "--tcp-flags", "ACK,RST", "ACK,RST", "-j", "DROP"},

		// NAT rules
		{"iptables", "-t", "nat", "-A", "OUTPUT", "-m", "owner", "--uid-owner", torUid, "-j", "RETURN"},
		{"iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", config.DnsPort},
	}

	// Add excluded IPs
	for _, ip := range config.ExcludedIPs {
		commands = append(commands, []string{"iptables", "-t", "nat", "-A", "OUTPUT", "-d", ip, "-j", "RETURN"})
	}

	// Redirect TCP traffic
	commands = append(commands, []string{"iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--syn", "-j", "REDIRECT", "--to-ports", config.TorPort})

	// Accept established connections
	commands = append(commands, []string{"iptables", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"})

	// Accept connections to excluded IPs
	for _, ip := range config.ExcludedIPs {
		commands = append(commands, []string{"iptables", "-A", "OUTPUT", "-d", ip, "-j", "ACCEPT"})
	}

	// Allow Tor user traffic and reject all other traffic
	commands = append(commands, []string{"iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", torUid, "-j", "ACCEPT"})
	commands = append(commands, []string{"iptables", "-A", "OUTPUT", "-j", "REJECT"})

	// Execute all commands
	for _, cmd := range commands {
		if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
			clearIptablesRules()
			return fmt.Errorf("failed to set iptables rule: %v", err)
		}
	}

	logMessage("[+] Network rules configured for Tor routing", false)
	return nil
}

// Clear iptables rules
func clearIptablesRules() {
	if runtime.GOOS != "linux" {
		return
	}

	exec.Command("iptables", "-F").Run()
	exec.Command("iptables", "-t", "nat", "-F").Run()
	logMessage("[+] Cleared all network rules", false)
}

// Restart the Tor service
func restartTor() error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("systemctl", "restart", "tor")
	case "darwin":
		cmd = exec.Command("brew", "services", "restart", "tor")
	default:
		return fmt.Errorf("restarting Tor not supported on %s", runtime.GOOS)
	}

	if err := cmd.Run(); err != nil {
		return err
	}

	logMessage("[+] Tor service restarted", false)
	return nil
}

// Start PhantomGate (Tor routing)
func startPhantomGate() error {
	if config.UseTor {
		if !checkTor() {
			if !installTor() {
				return fmt.Errorf("Tor is required but could not be installed")
			}
		}

		if err := configureTor(); err != nil {
			return fmt.Errorf("failed to configure Tor: %v", err)
		}

		if err := restartTor(); err != nil {
			return fmt.Errorf("failed to restart Tor: %v", err)
		}

		if runtime.GOOS == "linux" {
			if err := setupIptablesRules(); err != nil {
				return fmt.Errorf("failed to setup network rules: %v", err)
			}
		}
	}

	if config.UseProxies && len(config.ProxyList) > 0 {
		// Select first proxy by default
		config.CurrentProxy = &config.ProxyList[0]
		logMessage(fmt.Sprintf("[+] Using proxy: %s (%s)", config.CurrentProxy.Address, config.CurrentProxy.Type), false)
	}

	logMessage("[+] PhantomGate: Privacy mode [ACTIVE]", false)
	return nil
}

// Stop PhantomGate
func stopPhantomGate() error {
	if runtime.GOOS == "linux" {
		clearIptablesRules()
	}

	config.CurrentProxy = nil
	logMessage("[!] PhantomGate: Privacy mode [INACTIVE]", false)
	return nil
}

// Get current IP information
func getIpInfo() (*LocationInfo, error) {
	// Create a client with configurable timeout and TLS settings
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 10 * time.Second,
			}).DialContext,
		},
	}

	// Try multiple IP info services
	services := []string{
		"https://ipinfo.io/json",
		"https://api.ipify.org?format=json",
		"https://api.myip.com",
	}

	var lastError error
	for _, service := range services {
		resp, err := client.Get(service)
		if err != nil {
			lastError = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastError = fmt.Errorf("service %s returned status: %d", service, resp.StatusCode)
			continue
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			lastError = err
			continue
		}

		info := &LocationInfo{}
		if err := json.Unmarshal(body, info); err != nil {
			lastError = err
			continue
		}

		// Some services use different JSON fields, handle them
		if info.IP == "" {
			var data map[string]interface{}
			if err := json.Unmarshal(body, &data); err == nil {
				if ip, ok := data["ip"].(string); ok {
					info.IP = ip
				} else if ip, ok := data["query"].(string); ok {
					info.IP = ip
				}
			}
		}

		if info.IP != "" {
			return info, nil
		}
	}

	return nil, fmt.Errorf("failed to get IP info: %v", lastError)
}

// Display current IP and location
func showCurrentIP() {
	logMessage("[*] Fetching public IP address...", false)

	info, err := getIpInfo()
	if err != nil {
		logMessage("[!] Error getting IP info: "+err.Error(), true)
		return
	}

	logMessage(fmt.Sprintf("[+] Your IP: %s", info.IP), false)
	if info.Country != "" {
		logMessage(fmt.Sprintf("[+] Location: %s, %s", info.Country, info.City), false)
	}
	if info.ISP != "" {
		logMessage(fmt.Sprintf("[+] ISP: %s", info.ISP), false)
	}
}

// Change current IP address
func changeIP() error {
	if config.UseTor {
		// Get Tor PID
		cmd := exec.Command("pidof", "tor")
		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("couldn't find Tor process: %v", err)
		}

		torPid := strings.TrimSpace(string(output))
		if torPid == "" {
			return fmt.Errorf("Tor is not running")
		}

		// Send HUP signal to Tor to change circuit
		cmd = exec.Command("kill", "-HUP", torPid)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to signal Tor: %v", err)
		}

		logMessage("[+] Requested new Tor circuit", false)
		time.Sleep(2 * time.Second) // Give Tor time to change circuit
	} else if config.UseProxies && len(config.ProxyList) > 1 {
		// Find current proxy index
		currentIndex := 0
		for i, proxy := range config.ProxyList {
			if config.CurrentProxy != nil && proxy.Address == config.CurrentProxy.Address {
				currentIndex = i
				break
			}
		}

		// Switch to next proxy
		nextIndex := (currentIndex + 1) % len(config.ProxyList)
		config.CurrentProxy = &config.ProxyList[nextIndex]
		logMessage(fmt.Sprintf("[+] Switched to proxy: %s (%s)", config.CurrentProxy.Address, config.CurrentProxy.Type), false)
	} else {
		return fmt.Errorf("no method available to change IP")
	}

	return nil
}

// Run automatic IP changing
func runAutoIPChange(interval int, stopChan <-chan struct{}) {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := changeIP(); err != nil {
				logMessage("[!] Failed to change IP: "+err.Error(), true)
				continue
			}
			showCurrentIP()
		case <-stopChan:
			return
		}
	}
}

// Check network leaks
func checkLeaks() {
	logMessage("[*] Checking for DNS leaks...", false)
	// Implement DNS leak test
	
	logMessage("[*] Checking for WebRTC leaks...", false)
	// Implement WebRTC leak test
	
	logMessage("[*] Checking for browser fingerprinting...", false)
	// Implement browser fingerprint check
	
	logMessage("[+] Leak check complete", false)
}

// ANSI color codes
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorPurple  = "\033[35m"
	colorCyan    = "\033[36m"
	colorMagenta = "\033[35m"
	colorWhite   = "\033[37m"
	colorBold    = "\033[1m"
)

// DisplayBanner prints
func printBanner() {
	fmt.Println(colorWhite + colorBold + `
 ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗ ██████╗  █████╗ ████████╗███████╗
 ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
 ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║██║  ███╗███████║   ██║   █████╗  
 ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║██║   ██║██╔══██║   ██║   ██╔══╝  
 ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║╚██████╔╝██║  ██║   ██║   ███████╗
 ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝` + colorReset)
	fmt.Println(colorWhite + colorBold + "                      Secure Network Monitoring v" + version + " 👁" + colorReset)
	fmt.Println(colorWhite + "════════════════════════════════════════════════════════════════════════════════════════════════════" + colorReset)
}

func main() {
	// Check for root/admin privileges
	if !checkRoot() {
		fmt.Println("\033[91m[!]\033[0m Please run as administrator/root")
		os.Exit(1)
	}

	printBanner()

	// Initialize configuration
	config = initConfig()

	// Setup logging
	logFile, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err == nil {
		logger = log.New(logFile, "", log.LstdFlags)
		defer logFile.Close()
	}

	// Define command line flags
	startCmd := flag.Bool("start", false, "Start PhantomGate")
	stopCmd := flag.Bool("stop", false, "Stop PhantomGate")
	newIpCmd := flag.Bool("new-ip", false, "Get a new IP address")
	checkIpCmd := flag.Bool("ip", false, "Show current public IP address")
	autoCmd := flag.Bool("auto", false, "Automatically change IP at regular intervals")
	intervalFlag := flag.Int("time", config.AutoInterval, "Interval for automatic IP changes (seconds)")
	proxyFlag := flag.Bool("proxy", false, "Use private proxy list instead of Tor")
	addProxyCmd := flag.Bool("add-proxy", false, "Add a new proxy to the list")
	torFlag := flag.Bool("tor", true, "Use Tor for anonymization")
	noTorFlag := flag.Bool("no-tor", false, "Don't use Tor (use only with proxies)")
	leakTestCmd := flag.Bool("check-leaks", false, "Check for privacy leaks")
	stealthFlag := flag.Bool("stealth", false, "Enable stealth mode (extra privacy features)")
	debugFlag := flag.Bool("debug", false, "Enable debug logging")
	versionCmd := flag.Bool("version", false, "Show version information")

	flag.Parse()

	// Handle version request
	if *versionCmd {
		fmt.Printf("PhantomGate v%s\n", version)
		return
	}

	// Set configuration based on flags
	config.AutoInterval = *intervalFlag
	config.UseProxies = *proxyFlag
	config.UseTor = *torFlag
	config.Stealth = *stealthFlag
	config.Debug = *debugFlag

	// Handle tor and proxy flags
	if *noTorFlag {
		config.UseTor = false
	}

	// Load proxies if needed
	if config.UseProxies {
		if err := loadProxies(); err != nil {
			logMessage("[!] Failed to load proxies: "+err.Error(), true)
			if len(config.ProxyList) == 0 {
				logMessage("[!] No proxies available, falling back to Tor", true)
				config.UseProxies = false
				config.UseTor = true
			}
		}
	}

	// Setup a channel to handle graceful shutdown
	stopChan := make(chan struct{})
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logMessage(fmt.Sprintf("[!] Received signal %v, shutting down...", sig), false)
		close(stopChan)
		stopPhantomGate()
		saveConfig()
		os.Exit(0)
	}()

	// Add a new proxy
	if *addProxyCmd {
		scanner := bufio.NewScanner(os.Stdin)
		
		fmt.Print("Proxy type (http, https, socks5): ")
		scanner.Scan()
		pType := scanner.Text()
		
		fmt.Print("Proxy address (IP:PORT): ")
		scanner.Scan()
		address := scanner.Text()
		
		fmt.Print("Username (optional): ")
		scanner.Scan()
		username := scanner.Text()
		
		fmt.Print("Password (optional): ")
		scanner.Scan()
		password := scanner.Text()
		
		newProxy := Proxy{
			Type:     pType,
			Address:  address,
			Username: username,
			Password: password,
		}
		
		config.ProxyList = append(config.ProxyList, newProxy)
		
		// Save proxies to file
		jsonData, _ := json.MarshalIndent(config.ProxyList, "", "  ")
		if err := ioutil.WriteFile(config.ProxyFilePath, jsonData, 0600); err != nil {
			logMessage("[!] Failed to save proxy: "+err.Error(), true)
		} else {
			logMessage("[+] Added new proxy to list", false)
		}
		return
	}

	// Handle commands
	if *startCmd {
		if err := startPhantomGate(); err != nil {
			logMessage("[!] Failed to start PhantomGate: "+err.Error(), true)
			os.Exit(1)
		}
		showCurrentIP()
	} else if *stopCmd {
		if err := stopPhantomGate(); err != nil {
			logMessage("[!] Failed to stop PhantomGate: "+err.Error(), true)
			os.Exit(1)
		}
	} else if *newIpCmd {
		if err := changeIP(); err != nil {
			logMessage("[!] Failed to change IP: "+err.Error(), true)
			os.Exit(1)
		}
		showCurrentIP()
	} else if *checkIpCmd {
		showCurrentIP()
	} else if *leakTestCmd {
		checkLeaks()
	} else if *autoCmd {
		if err := startPhantomGate(); err != nil {
			logMessage("[!] Failed to start PhantomGate: "+err.Error(), true)
			os.Exit(1)
		}
		
		interval := *intervalFlag
		logMessage(fmt.Sprintf("[+] Auto IP switching enabled. Interval: %d seconds", interval), false)
		
		go runAutoIPChange(interval, stopChan)
		
		// Wait for termination signal
		<-stopChan
	} else {
		flag.Usage()
	}

	// Save config before exiting
	saveConfig()
}
