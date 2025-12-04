package main

import (
	"archive/zip"
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	toml "github.com/pelletier/go-toml/v2"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

const (
	ClientConfigDir   = "/root/frp/client"
	ServerConfigDir   = "/root/frp/server"
	PresetsFile       = "/root/frp/presets.json"
	ServerPresetsFile = "/root/frp/server_presets.json"
	UsersFile         = "/root/frp/users.json"
	SettingsFile      = "/root/frp/settings.json"
)

// --- Struct Definitions ---

type SystemInfo struct {
	CPUUsage        float64 `json:"cpu_usage"`
	RAMUsed         uint64  `json:"ram_used"`
	RAMTotal        uint64  `json:"ram_total"`
	NetworkUpload   uint64  `json:"network_upload"`
	NetworkDownload uint64  `json:"network_download"`
}

type User struct {
	Username     string
	PasswordHash string
}

type Session struct {
	Username  string
	CreatedAt time.Time
}

type Preset struct {
	Name       string `json:"name"`
	ServerIP   string `json:"server_ip"`
	ServerPort string `json:"server_port"`
	AuthToken  string `json:"auth_token"`
	Transport  string `json:"transport"`
	UseMux     bool   `json:"use_mux"`
}

type ServerPreset struct {
	Name        string `json:"name"`
	BindPort    string `json:"bind_port"`
	ProtoChoice string `json:"proto_choice"`
	UseMux      bool   `json:"use_mux"`
	Token       string `json:"token"`
}

type NetworkDataPoint struct {
	Timestamp       time.Time `json:"timestamp"`
	NetworkUpload   uint64    `json:"network_upload"`
	NetworkDownload uint64    `json:"network_download"`
}

type FRPStatus struct {
	TotalClients int      `json:"total_clients"`
	TotalProxies int      `json:"total_proxies"`
	ClientList   []string `json:"client_list"`
}

type ConnectionStatus struct {
	Name       string `json:"name"`
	Status     string `json:"status"` // "running", "warning", "error", "stopped"
	TrafficIn  int64  `json:"traffic_in"`
	TrafficOut int64  `json:"traffic_out"`
	CurConns   int64  `json:"cur_conns"`
}

type PanelSettings struct {
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
}

// --- Global Variables ---

var (
	lastNetStats       map[string]net.IOCountersStat
	lastNetTime        time.Time
	sessions           = make(map[string]Session)
	users              map[string]User
	usersMutex         sync.RWMutex
	panelSettings      PanelSettings
	settingsMutex      sync.RWMutex
	upgrader           = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	networkHistory     []NetworkDataPoint
	historyMutex       sync.RWMutex
	presets            map[string]Preset
	presetsMutex       sync.Mutex
	serverPresets      map[string]ServerPreset
	serverPresetsMutex sync.Mutex

	// CPU calculation state
	cpuMu       sync.Mutex
	lastTotal   uint64
	lastIdleAll uint64
	lastSteal   uint64
	hasLast     bool
)

func main() {
	// Initialize state
	lastNetStats = make(map[string]net.IOCountersStat)
	lastNetTime = time.Now()
	users = make(map[string]User)
	loadUsers()
	loadPanelSettings()
	presets = make(map[string]Preset)
	serverPresets = make(map[string]ServerPreset)
	loadPresets()
	loadServerPresets()

	// Start background tasks
	go recordNetworkHistory()

	r := gin.Default()
	r.LoadHTMLGlob("templates/*.html")
	r.Static("/static", "./static")

	// Public routes
	r.GET("/login", loginForm)
	r.POST("/login", login)

	// Protected routes
	protected := r.Group("/")
	protected.Use(authRequired())
	{
		// --- API Routes ---
		protected.GET("/api/system/info", systemInfoHandler)
		protected.GET("/api/system/history", networkHistoryHandler)
		protected.GET("/api/frp/status", frpStatusHandler)
		protected.GET("/api/connections/status", connectionStatusHandler)
		protected.GET("/api/presets", getPresets)
		protected.POST("/api/presets/save", savePreset)
		protected.POST("/api/presets/delete", deletePreset)
		protected.GET("/api/presets/server", getServerPresets)
		protected.POST("/api/presets/server/save", saveServerPreset)
		protected.POST("/api/presets/server/delete", deleteServerPreset)
		protected.GET("/api/logs/:type/:name", queryLogs)
		protected.GET("/ws/logs/:type/:name", streamLogs)

		// Backup & SSL
		protected.GET("/api/backup/download", downloadBackup)
		protected.POST("/api/backup/upload", uploadBackup)
		protected.POST("/api/settings/ssl", updateSSLSettings)

		// --- Page Routes ---
		protected.GET("/", home)
		protected.GET("/logout", logout)
		protected.GET("/setup-frp", setupFRPForm)
		protected.GET("/manage-frp", manageFRP)
		protected.GET("/settings", showSettingsForm)
		protected.POST("/settings", updateSettings)

		// --- Setup/Action Routes ---
		protected.POST("/setup-server", setupServer)
		protected.POST("/setup-client", setupClient)

		// --- Management Routes ---
		protected.GET("/client/start/:name", clientStart)
		protected.GET("/client/stop/:name", clientStop)
		protected.GET("/client/restart/:name", clientRestart)
		protected.POST("/client/delete/:name", clientDelete)
		protected.GET("/client/start_all", clientStartAll)
		protected.GET("/client/stop_all", clientStopAll)
		protected.GET("/client/restart_all", clientRestartAll)
		protected.POST("/client/set_domain_all", setAllClientDomains)
		protected.GET("/client/edit/:name", clientEditForm)
		protected.POST("/client/edit/:name", clientEdit)

		protected.GET("/server/start/:name", serverStart)
		protected.GET("/server/stop/:name", serverStop)
		protected.GET("/server/restart/:name", serverRestart)
		protected.POST("/server/delete/:name", serverDelete)
		protected.GET("/server/start_all", serverStartAll)
		protected.GET("/server/stop_all", serverStopAll)
		protected.GET("/server/restart_all", serverRestartAll)
		protected.GET("/server/edit/:name", serverEditForm)
		protected.POST("/server/edit/:name", serverEdit)

		// --- Other Routes ---
		protected.GET("/efrp", efrp)
		protected.GET("/efrp/start", efrpStart)
		protected.GET("/efrp/stop", efrpStop)
		protected.GET("/status", showStatus)
		protected.POST("/install", installFRP)
		protected.GET("/remove", removeForm)
		protected.POST("/remove", removeFRP)
	}

	addr := ":5001"
	if panelSettings.CertPath != "" && panelSettings.KeyPath != "" {
		fmt.Printf("Server starting on HTTPS %s...\n", addr)
		if err := r.RunTLS(addr, panelSettings.CertPath, panelSettings.KeyPath); err != nil {
			log.Fatalf("Failed to start HTTPS server: %v", err)
		}
	} else {
		fmt.Printf("Server starting on HTTP %s...\n", addr)
		r.Run(addr)
	}
}

// --- Backup & Settings Handlers ---

func loadPanelSettings() {
	settingsMutex.Lock()
	defer settingsMutex.Unlock()
	file, err := ioutil.ReadFile(SettingsFile)
	if err == nil {
		json.Unmarshal(file, &panelSettings)
	}
}

func savePanelSettingsToFile() error {
	settingsMutex.Lock()
	defer settingsMutex.Unlock()
	data, err := json.MarshalIndent(panelSettings, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(SettingsFile, data, 0644)
}

func updateSSLSettings(c *gin.Context) {
	certPath := c.PostForm("cert_path")
	keyPath := c.PostForm("key_path")

	panelSettings.CertPath = certPath
	panelSettings.KeyPath = keyPath

	if err := savePanelSettingsToFile(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save settings"})
		return
	}
	// Restart logic
	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "SSL settings saved. Restarting panel..."})
	go func() {
		time.Sleep(1 * time.Second)
		os.Exit(0) // Exit process; systemd should restart it
	}()
}

func downloadBackup(c *gin.Context) {
	c.Header("Content-Disposition", "attachment; filename=frp_backup.zip")
	c.Header("Content-Type", "application/zip")

	zipWriter := zip.NewWriter(c.Writer)
	defer zipWriter.Close()

	root := "/root/frp"
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		// Create relative path
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		zipFile, err := zipWriter.Create(relPath)
		if err != nil {
			return err
		}

		fsFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer fsFile.Close()

		_, err = io.Copy(zipFile, fsFile)
		return err
	})
}

func uploadBackup(c *gin.Context) {
	file, err := c.FormFile("backup_file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
		return
	}

	dst := "/tmp/restore.zip"
	if err := c.SaveUploadedFile(file, dst); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}

	// Unzip and restore
	archive, err := zip.OpenReader(dst)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open zip"})
		return
	}
	defer archive.Close()

	// Stop all services before restore
	stopAllServices()

	for _, f := range archive.File {
		fpath := filepath.Join("/root/frp", f.Name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			continue
		}
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			continue
		}
		io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Backup restored. Please restart services manually or via dashboard."})
}

func stopAllServices() {
	// Quick helper to stop known services
	units := runCmdOutput("systemctl", "list-units", "frp*", "--state=running", "--no-pager", "--plain")
	scanner := bufio.NewScanner(strings.NewReader(units))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 {
			runCmd("systemctl", "stop", fields[0])
		}
	}
}

// --- Connection Status with Metrics ---

func connectionStatusHandler(c *gin.Context) {
	var clients []ConnectionStatus
	var servers []ConnectionStatus

	// Helper to fetch metrics
	getMetrics := func(configPath string) (int64, int64, int64) {
		// Logic to parse TOML and fetch from admin port
		// 1. Read file
		content, err := ioutil.ReadFile(configPath)
		if err != nil {
			return 0, 0, 0
		}

		// 2. Parse basic TOML to find webServer.port (or admin_port)
		var cfg map[string]interface{}
		if err := toml.Unmarshal(content, &cfg); err != nil {
			return 0, 0, 0
		}

		// Check for webServer section
		var port int
		if ws, ok := cfg["webServer"].(map[string]interface{}); ok {
			if p, ok := ws["port"].(float64); ok { // JSON/TOML unmarshal often gives float64 for generic numbers
				port = int(p)
			} else if p, ok := ws["port"].(int64); ok {
				port = int(p)
			}
		} else if ap, ok := cfg["adminPort"].(int64); ok { // Legacy/Other style
			port = int(ap)
		}

		if port == 0 {
			return 0, 0, 0
		}

		// 3. Query metrics
		client := http.Client{Timeout: 500 * time.Millisecond}
		// Try TCP stats
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/proxy/tcp", port))
		if err != nil {
			return 0, 0, 0
		}
		defer resp.Body.Close()

		// Parse Response: {"proxies": [{"name": "...", "today_traffic_in": 123, "today_traffic_out": 456, "cur_conns": 1}]}
		var apiResp struct {
			Proxies []struct {
				TrafficIn  int64 `json:"today_traffic_in"`
				TrafficOut int64 `json:"today_traffic_out"`
				CurConns   int64 `json:"cur_conns"`
			} `json:"proxies"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err == nil {
			var tIn, tOut, conns int64
			for _, p := range apiResp.Proxies {
				tIn += p.TrafficIn
				tOut += p.TrafficOut
				conns += p.CurConns
			}
			return tIn, tOut, conns
		}
		return 0, 0, 0
	}

	clientFiles, _ := filepath.Glob(filepath.Join(ClientConfigDir, "*.toml"))
	for _, f := range clientFiles {
		name := strings.TrimSuffix(filepath.Base(f), ".toml")
		status := getServiceStatus("frpc@" + name)
		tIn, tOut, conns := getMetrics(f)
		clients = append(clients, ConnectionStatus{Name: name, Status: status, TrafficIn: tIn, TrafficOut: tOut, CurConns: conns})
	}

	serverFiles, _ := filepath.Glob(filepath.Join(ServerConfigDir, "*.toml"))
	for _, f := range serverFiles {
		name := strings.TrimSuffix(filepath.Base(f), ".toml")
		status := getServiceStatus("frps@" + name)
		tIn, tOut, conns := getMetrics(f)
		servers = append(servers, ConnectionStatus{Name: name, Status: status, TrafficIn: tIn, TrafficOut: tOut, CurConns: conns})
	}

	c.JSON(http.StatusOK, gin.H{
		"clients": clients,
		"servers": servers,
	})
}

// --- Deletion Handlers ---

func clientDelete(c *gin.Context) {
	deleteConfigAndService(c, "client")
}

func serverDelete(c *gin.Context) {
	deleteConfigAndService(c, "server")
}

func deleteConfigAndService(c *gin.Context, configType string) {
	name := c.Param("name")
	var serviceName, configDir string
	if configType == "client" {
		serviceName = "frpc@" + name
		configDir = ClientConfigDir
	} else {
		serviceName = "frps@" + name
		configDir = ServerConfigDir
	}

	// Stop and Disable
	runCmd("systemctl", "stop", serviceName)
	runCmd("systemctl", "disable", serviceName)

	// Remove File
	path := filepath.Join(configDir, name+".toml")
	if err := os.Remove(path); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove config file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Configuration deleted"})
}

// --- Previous Handlers (Keep Existing Logic) ---

func setupFRPForm(c *gin.Context) {
	username, _ := c.Get("username")
	c.HTML(http.StatusOK, "setup-frp.html", gin.H{
		"Username": username,
	})
}

func manageFRP(c *gin.Context) {
	clientFiles, _ := filepath.Glob(filepath.Join(ClientConfigDir, "*.toml"))
	var clientList []string
	for _, f := range clientFiles {
		name := strings.TrimSuffix(filepath.Base(f), ".toml")
		clientList = append(clientList, name)
	}
	serverFiles, _ := filepath.Glob(filepath.Join(ServerConfigDir, "*.toml"))
	var serverList []string
	for _, f := range serverFiles {
		name := strings.TrimSuffix(filepath.Base(f), ".toml")
		serverList = append(serverList, name)
	}
	username, _ := c.Get("username")
	c.HTML(http.StatusOK, "manage-frp.html", gin.H{
		"Username": username,
		"Clients":  clientList,
		"Servers":  serverList,
	})
}

func showSettingsForm(c *gin.Context) {
	username, _ := c.Get("username")
	c.HTML(http.StatusOK, "settings.html", gin.H{
		"Username": username,
		"CertPath": panelSettings.CertPath,
		"KeyPath":  panelSettings.KeyPath,
		"Error":    c.Query("error"),
		"Success":  c.Query("success"),
	})
}

func updateSettings(c *gin.Context) {
	sessionUsername, _ := c.Get("username")
	usernameStr := sessionUsername.(string)
	newUsername := c.PostForm("new_username")
	currentPassword := c.PostForm("current_password")
	newPassword := c.PostForm("new_password")
	confirmPassword := c.PostForm("confirm_password")

	if newUsername == "" || currentPassword == "" {
		c.Redirect(http.StatusFound, "/settings?error="+url.QueryEscape("Required fields missing."))
		return
	}
	if newPassword != confirmPassword {
		c.Redirect(http.StatusFound, "/settings?error="+url.QueryEscape("Passwords do not match."))
		return
	}

	usersMutex.Lock()
	defer usersMutex.Unlock()
	user, exists := users[usernameStr]
	if !exists || !verifyPassword(currentPassword, user.PasswordHash) {
		c.Redirect(http.StatusFound, "/settings?error="+url.QueryEscape("Incorrect password."))
		return
	}
	if newUsername != usernameStr {
		if _, userExists := users[newUsername]; userExists {
			c.Redirect(http.StatusFound, "/settings?error="+url.QueryEscape("Username taken."))
			return
		}
	}

	newPasswordHash := user.PasswordHash
	if newPassword != "" {
		newPasswordHash = hashPassword(newPassword)
	}
	updatedUser := User{Username: newUsername, PasswordHash: newPasswordHash}
	if newUsername != usernameStr {
		delete(users, usernameStr)
	}
	users[newUsername] = updatedUser
	saveUsersToFileInternal()

	// Logout
	sessionID, _ := c.Cookie("frp-session")
	delete(sessions, sessionID)
	c.SetCookie("frp-session", "", -1, "/", "", false, true)
	c.Redirect(http.StatusFound, "/login?message="+url.QueryEscape("Settings updated."))
}

func recordNetworkHistory() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		info, err := getSystemInfo()
		if err != nil {
			continue
		}
		historyMutex.Lock()
		networkHistory = append(networkHistory, NetworkDataPoint{
			Timestamp:       time.Now(),
			NetworkUpload:   info.NetworkUpload,
			NetworkDownload: info.NetworkDownload,
		})
		if len(networkHistory) > 60 {
			networkHistory = networkHistory[1:]
		}
		historyMutex.Unlock()
	}
}

func networkHistoryHandler(c *gin.Context) {
	historyMutex.RLock()
	defer historyMutex.RUnlock()
	c.JSON(http.StatusOK, networkHistory)
}

func frpStatusHandler(c *gin.Context) {
	status := FRPStatus{ClientList: make([]string, 0)}
	clientIDs := make(map[string]bool)
	proxyCount := 0
	output := runCmdOutput("systemctl", "list-units", "frps@*.service", "--state=running", "--no-pager", "--plain")
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.HasPrefix(fields[0], "frps@") {
			serviceName := fields[0]
			logOutput := runCmdOutput("journalctl", "-u", serviceName, "-n", "200", "--no-pager")
			clientRegex := regexp.MustCompile(`\[([0-9a-f]{16})\] client login`)
			matches := clientRegex.FindAllStringSubmatch(logOutput, -1)
			for _, match := range matches {
				if len(match) > 1 {
					clientIDs[match[1]] = true
				}
			}
			proxyRegex := regexp.MustCompile(`new proxy`)
			proxyCount += len(proxyRegex.FindAllString(logOutput, -1))
		}
	}
	status.TotalClients = len(clientIDs)
	status.TotalProxies = proxyCount
	for id := range clientIDs {
		status.ClientList = append(status.ClientList, id)
	}
	c.JSON(http.StatusOK, status)
}

func getServiceStatus(serviceName string) string {
	if !isActive(serviceName) {
		return "stopped"
	}
	logOutput := runCmdOutput("journalctl", "-u", serviceName, "-n", "20", "--no-pager")
	if regexp.MustCompile(`(?i)(\[E\]|error|fail)`).MatchString(logOutput) {
		return "error"
	}
	if regexp.MustCompile(`(?i)(\[W\]|warn)`).MatchString(logOutput) {
		return "warning"
	}
	return "running"
}

func queryLogs(c *gin.Context) {
	logType := c.Param("type")
	name := c.Param("name")
	since := c.Query("since")
	var serviceName string
	switch logType {
	case "client":
		serviceName = "frpc@" + name
	case "server":
		serviceName = "frps@" + name
	case "efrp":
		serviceName = "EFRP.service"
	default:
		c.String(http.StatusBadRequest, "Invalid log type")
		return
	}
	args := []string{"-u", serviceName, "--no-pager"}
	if since != "" {
		args = append(args, "--since", since)
	} else {
		args = append(args, "-n", "500")
	}
	out, err := exec.Command("journalctl", args...).CombinedOutput()
	if err != nil {
		c.String(http.StatusInternalServerError, fmt.Sprintf("Error fetching logs: %v", err))
		return
	}
	c.String(http.StatusOK, string(out))
}

func streamLogs(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	logType := c.Param("type")
	name := c.Param("name")
	var serviceName string
	switch logType {
	case "client":
		serviceName = "frpc@" + name
	case "server":
		serviceName = "frps@" + name
	case "efrp":
		serviceName = "EFRP.service"
	default:
		conn.WriteMessage(websocket.TextMessage, []byte("Invalid log type"))
		return
	}
	cmd := exec.Command("journalctl", "-f", "-u", serviceName, "-n", "20", "--no-pager")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		if err := conn.WriteMessage(websocket.TextMessage, scanner.Bytes()); err != nil {
			break
		}
	}
	cmd.Process.Kill()
}

func loadPresets() {
	presetsMutex.Lock()
	defer presetsMutex.Unlock()
	file, err := ioutil.ReadFile(PresetsFile)
	if err == nil {
		json.Unmarshal(file, &presets)
	}
}

func savePresetsToFile() error {
	presetsMutex.Lock()
	defer presetsMutex.Unlock()
	data, err := json.MarshalIndent(presets, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(PresetsFile, data, 0644)
}

func getPresets(c *gin.Context) {
	presetsMutex.Lock()
	defer presetsMutex.Unlock()
	c.JSON(http.StatusOK, presets)
}

func savePreset(c *gin.Context) {
	var preset Preset
	if err := c.ShouldBindJSON(&preset); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid data"})
		return
	}
	if preset.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Name empty"})
		return
	}
	presets[preset.Name] = preset
	savePresetsToFile()
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func deletePreset(c *gin.Context) {
	var data map[string]string
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	delete(presets, data["name"])
	savePresetsToFile()
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func loadServerPresets() {
	serverPresetsMutex.Lock()
	defer serverPresetsMutex.Unlock()
	file, err := ioutil.ReadFile(ServerPresetsFile)
	if err == nil {
		json.Unmarshal(file, &serverPresets)
	}
}

func saveServerPresetsToFile() error {
	serverPresetsMutex.Lock()
	defer serverPresetsMutex.Unlock()
	data, err := json.MarshalIndent(serverPresets, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(ServerPresetsFile, data, 0644)
}

func getServerPresets(c *gin.Context) {
	serverPresetsMutex.Lock()
	defer serverPresetsMutex.Unlock()
	c.JSON(http.StatusOK, serverPresets)
}

func saveServerPreset(c *gin.Context) {
	var preset ServerPreset
	if err := c.ShouldBindJSON(&preset); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid data"})
		return
	}
	if preset.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Name empty"})
		return
	}
	serverPresets[preset.Name] = preset
	saveServerPresetsToFile()
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func deleteServerPreset(c *gin.Context) {
	var data map[string]string
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	delete(serverPresets, data["name"])
	saveServerPresetsToFile()
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func saveUsersToFileInternal() error {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	os.MkdirAll(filepath.Dir(UsersFile), 0755)
	return ioutil.WriteFile(UsersFile, data, 0644)
}

func loadUsers() {
	usersMutex.Lock()
	defer usersMutex.Unlock()
	file, err := ioutil.ReadFile(UsersFile)
	if err != nil {
		if os.IsNotExist(err) {
			users = map[string]User{"admin": {Username: "admin", PasswordHash: "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"}}
			saveUsersToFileInternal()
		}
		return
	}
	json.Unmarshal(file, &users)
}

func authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID, err := c.Cookie("frp-session")
		if err != nil || sessionID == "" {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		session, exists := sessions[sessionID]
		if !exists || time.Since(session.CreatedAt) > 7*24*time.Hour {
			delete(sessions, sessionID)
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		c.Set("username", session.Username)
		c.Next()
	}
}

func loginForm(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{"Error": c.Query("error"), "Message": c.Query("message")})
}

func login(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	usersMutex.RLock()
	user, exists := users[username]
	usersMutex.RUnlock()
	if !exists || !verifyPassword(password, user.PasswordHash) {
		c.Redirect(http.StatusFound, "/login?error="+url.QueryEscape("Invalid username or password"))
		return
	}
	sessionID := generateSessionID()
	sessions[sessionID] = Session{Username: username, CreatedAt: time.Now()}
	c.SetCookie("frp-session", sessionID, 86400*7, "/", "", false, true)
	c.Redirect(http.StatusFound, "/")
}

func logout(c *gin.Context) {
	sessionID, _ := c.Cookie("frp-session")
	delete(sessions, sessionID)
	c.SetCookie("frp-session", "", -1, "/", "", false, true)
	c.Redirect(http.StatusFound, "/login")
}

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func verifyPassword(password, hash string) bool {
	return hashPassword(password) == hash
}

func generateSessionID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func systemInfoHandler(c *gin.Context) {
	info, err := getSystemInfo()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, info)
}

// CPUPercentRaw returns instantaneous total CPU utilization by reading /proc/stat.
// First call initializes and returns 0; subsequent calls return busy/total * 100.
// This implementation explicitly excludes 'steal' time from usage to reflect only server resource consumption.
func CPUPercentRaw() (float64, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	rd := bufio.NewReader(f)
	line, err := rd.ReadString('\n')
	if err != nil && err != io.EOF {
		return 0, err
	}
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, fmt.Errorf("unexpected /proc/stat format")
	}

	var nums []uint64
	for i := 1; i < len(fields); i++ {
		v, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			break
		}
		nums = append(nums, v)
	}
	if len(nums) < 4 {
		return 0, fmt.Errorf("insufficient cpu fields")
	}

	var user, nice, system, idle, iowait, irq, softirq, steal uint64
	user = nums[0]
	if len(nums) > 1 {
		nice = nums[1]
	}
	if len(nums) > 2 {
		system = nums[2]
	}
	if len(nums) > 3 {
		idle = nums[3]
	}
	if len(nums) > 4 {
		iowait = nums[4]
	}
	if len(nums) > 5 {
		irq = nums[5]
	}
	if len(nums) > 6 {
		softirq = nums[6]
	}
	if len(nums) > 7 {
		steal = nums[7]
	}

	idleAll := idle + iowait
	nonIdle := user + nice + system + irq + softirq + steal
	total := idleAll + nonIdle

	cpuMu.Lock()
	defer cpuMu.Unlock()

	if !hasLast {
		lastTotal = total
		lastIdleAll = idleAll
		lastSteal = steal
		hasLast = true
		return 0, nil
	}

	totald := total - lastTotal
	idled := idleAll - lastIdleAll
	steald := steal - lastSteal

	lastTotal = total
	lastIdleAll = idleAll
	lastSteal = steal

	if totald == 0 {
		return 0, nil
	}

	// busy time includes steal because nonIdle includes steal
	busy := totald - idled

	// We want to calculate usage EXCLUDING steal (only what the server used)
	serverBusy := busy
	if serverBusy >= steald {
		serverBusy -= steald
	}

	pct := float64(serverBusy) / float64(totald) * 100.0
	if pct > 100 {
		pct = 100
	}
	return pct, nil
}

func getSystemInfo() (*SystemInfo, error) {
	// Use custom CPU calculation
	usage, _ := CPUPercentRaw()

	memInfo, _ := mem.VirtualMemory()
	netStats, _ := net.IOCounters(false)
	var up, down uint64
	if len(netStats) > 0 {
		now := time.Now()
		if !lastNetTime.IsZero() {
			diff := now.Sub(lastNetTime).Seconds()
			if diff > 0 {
				var cUp, cDown, lUp, lDown uint64
				for _, s := range netStats {
					cUp += s.BytesSent
					cDown += s.BytesRecv
				}
				for _, s := range lastNetStats {
					lUp += s.BytesSent
					lDown += s.BytesRecv
				}
				up = uint64(float64(cUp-lUp) / diff)
				down = uint64(float64(cDown-lDown) / diff)
			}
		}
		lastNetStats = make(map[string]net.IOCountersStat)
		for _, s := range netStats {
			lastNetStats[s.Name] = s
		}
		lastNetTime = now
	}
	return &SystemInfo{CPUUsage: usage, RAMUsed: memInfo.Used, RAMTotal: memInfo.Total, NetworkUpload: up, NetworkDownload: down}, nil
}

func home(c *gin.Context) {
	u, _ := c.Get("username")
	c.HTML(http.StatusOK, "home.html", gin.H{"Username": u})
}

func installFRP(c *gin.Context) {
	optimize()
	arch := runtime.GOARCH
	if strings.HasPrefix(arch, "armv") {
		arch = "arm"
	}
	platform := fmt.Sprintf("%s_%s", runtime.GOOS, arch)
	resp, _ := http.Get("https://api.github.com/repos/fatedier/frp/releases/latest")
	defer resp.Body.Close()
	var rel struct {
		TagName string `json:"tag_name"`
	}
	json.NewDecoder(resp.Body).Decode(&rel)
	ver := strings.TrimPrefix(rel.TagName, "v")
	url := fmt.Sprintf("https://github.com/fatedier/frp/releases/download/v%s/frp_%s_%s.tar.gz", ver, ver, platform)
	exec.Command("curl", "-L", url, "-o", "/tmp/frp.tar.gz").Run()
	exec.Command("tar", "-xzf", "/tmp/frp.tar.gz", "-C", "/tmp").Run()
	dir := fmt.Sprintf("/tmp/frp_%s_%s", ver, platform)
	runCmd("cp", filepath.Join(dir, "frpc"), "/usr/local/bin/")
	runCmd("cp", filepath.Join(dir, "frps"), "/usr/local/bin/")
	runCmd("chmod", "+x", "/usr/local/bin/frpc", "/usr/local/bin/frps")
	runCmd("mkdir", "-p", ServerConfigDir)
	runCmd("mkdir", "-p", ClientConfigDir)
	runCmd("mkdir", "-p", filepath.Dir(PresetsFile))

	svcS := `[Unit]
Description=FRP Server (%i)
After=network.target
[Service]
ExecStart=/usr/local/bin/frps -c /root/frp/server/%i.toml
Restart=on-failure
RestartSec=5s
[Install]
WantedBy=multi-user.target`
	ioutil.WriteFile("/etc/systemd/system/frps@.service", []byte(svcS), 0644)

	svcC := `[Unit]
Description=FRP Client (%i)
After=network.target
[Service]
ExecStart=/usr/local/bin/frpc -c /root/frp/client/%i.toml
Restart=on-failure
RestartSec=5s
[Install]
WantedBy=multi-user.target`
	ioutil.WriteFile("/etc/systemd/system/frpc@.service", []byte(svcC), 0644)

	runCmd("systemctl", "daemon-reload")
	os.Remove("/tmp/frp.tar.gz")
	os.RemoveAll(dir)
	c.String(http.StatusOK, "Installed v"+ver)
}

func setupServer(c *gin.Context) {
	name := cleanName(c.PostForm("server_name"))
	if name == "" {
		c.String(400, "Invalid name")
		return
	}
	path := filepath.Join(ServerConfigDir, name+".toml")
	if _, err := os.Stat(path); err == nil {
		c.String(400, "Exists")
		return
	}
	f, _ := os.Create(path)
	defer f.Close()
	fmt.Fprint(f, "bindAddr = \"::\"\n")
	fmt.Fprintf(f, "bindPort = %s\n", c.PostForm("bind_port"))
	if c.PostForm("proto_choice") == "2" {
		fmt.Fprintf(f, "quicBindPort = %s\n", c.PostForm("bind_port"))
	} else if c.PostForm("proto_choice") == "3" {
		fmt.Fprintf(f, "kcpBindPort = %s\n", c.PostForm("bind_port"))
	}
	fmt.Fprintf(f, "transport.tcpMux = %s\n", c.PostForm("use_mux"))
	fmt.Fprintf(f, "auth.token = \"%s\"\n", c.PostForm("token"))

	runCmd("systemctl", "enable", "--now", "frps@"+name)
	c.Redirect(302, "/manage-frp")
}

func setupClient(c *gin.Context) {
	name := cleanName(c.PostForm("client_name"))
	if name == "" {
		c.String(400, "Invalid name")
		return
	}
	path := filepath.Join(ClientConfigDir, name+".toml")
	if _, err := os.Stat(path); err == nil {
		c.String(400, "Exists")
		return
	}
	f, _ := os.Create(path)
	defer f.Close()
	fmt.Fprintf(f, "serverAddr = \"%s\"\n", c.PostForm("server_ip"))
	fmt.Fprintf(f, "serverPort = %s\n", c.PostForm("server_port"))
	fmt.Fprintf(f, "auth.token = \"%s\"\n", c.PostForm("auth_token"))
	fmt.Fprintf(f, "transport.protocol = \"%s\"\n", c.PostForm("transport"))
	fmt.Fprintf(f, "transport.tcpMux = %s\n", c.PostForm("use_mux"))

	for _, p := range parsePorts(c.PostForm("port_input")) {
		fmt.Fprintf(f, "\n[[proxies]]\nname = \"tcp-%d\"\ntype = \"tcp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = %d\nremotePort = %d\n", p, p, p)
	}
	runCmd("systemctl", "enable", "--now", "frpc@"+name)
	c.Redirect(302, "/manage-frp")
}

func clientStart(c *gin.Context) {
	runCmd("systemctl", "start", "frpc@"+c.Param("name"))
	c.Redirect(302, "/manage-frp#clients:"+c.Param("name"))
}
func clientStop(c *gin.Context) {
	runCmd("systemctl", "stop", "frpc@"+c.Param("name"))
	c.Redirect(302, "/manage-frp#clients:"+c.Param("name"))
}
func clientRestart(c *gin.Context) {
	runCmd("systemctl", "restart", "frpc@"+c.Param("name"))
	c.Redirect(302, "/manage-frp#clients:"+c.Param("name"))
}
func clientStartAll(c *gin.Context) {
	files, _ := filepath.Glob(filepath.Join(ClientConfigDir, "*.toml"))
	for _, f := range files {
		runCmd("systemctl", "start", "frpc@"+strings.TrimSuffix(filepath.Base(f), ".toml"))
	}
	c.Redirect(302, "/manage-frp#clients")
}
func clientStopAll(c *gin.Context) {
	files, _ := filepath.Glob(filepath.Join(ClientConfigDir, "*.toml"))
	for _, f := range files {
		runCmd("systemctl", "stop", "frpc@"+strings.TrimSuffix(filepath.Base(f), ".toml"))
	}
	c.Redirect(302, "/manage-frp#clients")
}
func clientRestartAll(c *gin.Context) {
	files, _ := filepath.Glob(filepath.Join(ClientConfigDir, "*.toml"))
	for _, f := range files {
		runCmd("systemctl", "restart", "frpc@"+strings.TrimSuffix(filepath.Base(f), ".toml"))
	}
	c.Redirect(302, "/manage-frp#clients")
}

func setAllClientDomains(c *gin.Context) {
	d := c.PostForm("domain")
	files, _ := filepath.Glob(filepath.Join(ClientConfigDir, "*.toml"))
	re := regexp.MustCompile(`(serverAddr\s*=\s*")[^"]*(")`)
	rep := []byte("${1}" + d + "${2}")
	for _, f := range files {
		b, _ := ioutil.ReadFile(f)
		ioutil.WriteFile(f, re.ReplaceAll(b, rep), 0644)
		runCmd("systemctl", "restart", "frpc@"+strings.TrimSuffix(filepath.Base(f), ".toml"))
	}
	c.Redirect(302, "/manage-frp#clients")
}

func clientEditForm(c *gin.Context) {
	n := c.Param("name")
	b, _ := ioutil.ReadFile(filepath.Join(ClientConfigDir, n+".toml"))
	c.HTML(200, "edit.html", gin.H{"Content": string(b), "Name": n, "Type": "client"})
}
func clientEdit(c *gin.Context) {
	old := c.Param("name")
	new := cleanName(c.PostForm("name"))
	content := c.PostForm("content")

	if old != new {
		runCmd("systemctl", "disable", "--now", "frpc@"+old)
		os.Rename(filepath.Join(ClientConfigDir, old+".toml"), filepath.Join(ClientConfigDir, new+".toml"))
		ioutil.WriteFile(filepath.Join(ClientConfigDir, new+".toml"), []byte(content), 0644)
		runCmd("systemctl", "enable", "--now", "frpc@"+new)
		c.Redirect(302, "/manage-frp#clients:"+new)
	} else {
		ioutil.WriteFile(filepath.Join(ClientConfigDir, old+".toml"), []byte(content), 0644)
		runCmd("systemctl", "restart", "frpc@"+old)
		c.Redirect(302, "/manage-frp#clients:"+old)
	}
}

func serverStart(c *gin.Context) {
	runCmd("systemctl", "start", "frps@"+c.Param("name"))
	c.Redirect(302, "/manage-frp#servers:"+c.Param("name"))
}
func serverStop(c *gin.Context) {
	runCmd("systemctl", "stop", "frps@"+c.Param("name"))
	c.Redirect(302, "/manage-frp#servers:"+c.Param("name"))
}
func serverRestart(c *gin.Context) {
	runCmd("systemctl", "restart", "frps@"+c.Param("name"))
	c.Redirect(302, "/manage-frp#servers:"+c.Param("name"))
}
func serverStartAll(c *gin.Context) {
	files, _ := filepath.Glob(filepath.Join(ServerConfigDir, "*.toml"))
	for _, f := range files {
		runCmd("systemctl", "start", "frps@"+strings.TrimSuffix(filepath.Base(f), ".toml"))
	}
	c.Redirect(302, "/manage-frp#servers")
}
func serverStopAll(c *gin.Context) {
	files, _ := filepath.Glob(filepath.Join(ServerConfigDir, "*.toml"))
	for _, f := range files {
		runCmd("systemctl", "stop", "frps@"+strings.TrimSuffix(filepath.Base(f), ".toml"))
	}
	c.Redirect(302, "/manage-frp#servers")
}
func serverRestartAll(c *gin.Context) {
	files, _ := filepath.Glob(filepath.Join(ServerConfigDir, "*.toml"))
	for _, f := range files {
		runCmd("systemctl", "restart", "frps@"+strings.TrimSuffix(filepath.Base(f), ".toml"))
	}
	c.Redirect(302, "/manage-frp#servers")
}

func serverEditForm(c *gin.Context) {
	n := c.Param("name")
	b, _ := ioutil.ReadFile(filepath.Join(ServerConfigDir, n+".toml"))
	c.HTML(200, "edit.html", gin.H{"Content": string(b), "Name": n, "Type": "server"})
}
func serverEdit(c *gin.Context) {
	old := c.Param("name")
	new := cleanName(c.PostForm("name"))
	content := c.PostForm("content")
	if old != new {
		runCmd("systemctl", "disable", "--now", "frps@"+old)
		os.Rename(filepath.Join(ServerConfigDir, old+".toml"), filepath.Join(ServerConfigDir, new+".toml"))
		ioutil.WriteFile(filepath.Join(ServerConfigDir, new+".toml"), []byte(content), 0644)
		runCmd("systemctl", "enable", "--now", "frps@"+new)
		c.Redirect(302, "/manage-frp#servers:"+new)
	} else {
		ioutil.WriteFile(filepath.Join(ServerConfigDir, old+".toml"), []byte(content), 0644)
		runCmd("systemctl", "restart", "frps@"+old)
		c.Redirect(302, "/manage-frp#servers:"+old)
	}
}

func efrp(c *gin.Context) { c.HTML(200, "efrp.html", nil) }
func efrpStart(c *gin.Context) {
	runCmd("systemctl", "enable", "--now", "EFRP.service")
	c.Redirect(302, "/efrp")
}
func efrpStop(c *gin.Context) {
	runCmd("systemctl", "disable", "--now", "EFRP.service")
	c.Redirect(302, "/efrp")
}

func showStatus(c *gin.Context) {
	v := runCmdOutput("/usr/local/bin/frps", "--version")
	r := runCmdOutput("systemctl", "list-units", "--type=service", "--state=running")
	e := runCmdOutput("systemctl", "list-unit-files")
	c.HTML(200, "status.html", gin.H{"Version": v, "Running": r, "Enabled": e})
}

func removeForm(c *gin.Context) { c.HTML(200, "remove.html", nil) }
func removeFRP(c *gin.Context) {
	stopAllServices()
	os.Remove("/etc/systemd/system/frps@.service")
	os.Remove("/etc/systemd/system/frpc@.service")
	os.Remove("/usr/local/bin/frpc")
	os.Remove("/usr/local/bin/frps")
	os.RemoveAll("/root/frp")
	runCmd("systemctl", "daemon-reload")
	c.String(200, "Removed")
}

func optimize() { /* ... kept simple ... */ }
func cleanName(n string) string {
	return regexp.MustCompile("[^a-zA-Z0-9-]+").ReplaceAllString(strings.ReplaceAll(n, " ", "-"), "")
}
func parsePorts(s string) []int {
	var p []int
	for _, part := range strings.Split(s, ",") {
		if strings.Contains(part, "-") {
			sp := strings.Split(part, "-")
			start, _ := strconv.Atoi(sp[0])
			end, _ := strconv.Atoi(sp[1])
			for i := start; i <= end; i++ {
				p = append(p, i)
			}
		} else {
			pt, _ := strconv.Atoi(part)
			p = append(p, pt)
		}
	}
	return p
}
func runCmd(c ...string) { exec.Command(c[0], c[1:]...).Run() }
func runCmdOutput(c ...string) string {
	o, _ := exec.Command(c[0], c[1:]...).Output()
	return strings.TrimSpace(string(o))
}
func isActive(s string) bool {
	return strings.TrimSpace(string(runCmdOutput("systemctl", "is-active", s))) == "active"
}
