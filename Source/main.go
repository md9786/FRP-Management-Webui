package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
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
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

const (
	ClientConfigDir   = "/root/frp/client"
	ServerConfigDir   = "/root/frp/server"
	PresetsFile       = "/root/frp/presets.json"
	ServerPresetsFile = "/root/frp/server_presets.json"
	UsersFile         = "/root/frp/users.json"
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
	Name   string `json:"name"`
	Status string `json:"status"` // Can be "running", "warning", "error", "stopped"
}

// --- Global Variables ---

var (
	lastNetStats map[string]net.IOCountersStat
	lastNetTime  time.Time
	sessions     = make(map[string]Session)
	users        map[string]User
	usersMutex   sync.RWMutex
	upgrader     = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins for simplicity
		},
	}
	networkHistory     []NetworkDataPoint
	historyMutex       sync.RWMutex
	presets            map[string]Preset
	presetsMutex       sync.Mutex
	serverPresets      map[string]ServerPreset
	serverPresetsMutex sync.Mutex
)

func main() {
	// Initialize state
	lastNetStats = make(map[string]net.IOCountersStat)
	lastNetTime = time.Now()
	users = make(map[string]User)
	loadUsers()
	presets = make(map[string]Preset)
	serverPresets = make(map[string]ServerPreset)
	loadPresets()
	loadServerPresets()

	// Start background tasks
	go recordNetworkHistory()

	r := gin.Default()

	// Load HTML templates from the 'templates' directory
	r.LoadHTMLGlob("templates/*.html")

	r.Static("/static", "./static") // This might not be used if no static folder exists

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
		protected.GET("/ws/logs/:type/:name", streamLogs)

		// --- Page Routes ---
		protected.GET("/", home)
		protected.GET("/logout", logout)
		protected.GET("/setup-frp", setupFRPForm)
		protected.GET("/manage-frp", manageFRP)
		protected.GET("/settings", showSettingsForm)
		protected.POST("/settings", updateSettings)

		// --- Setup/Action Routes (Forms still post to these) ---
		protected.POST("/setup-server", setupServer)
		protected.POST("/setup-client", setupClient)

		// --- Management Routes ---
		protected.GET("/client/start/:name", clientStart)
		protected.GET("/client/stop/:name", clientStop)
		protected.GET("/client/restart/:name", clientRestart)
		protected.GET("/client/start_all", clientStartAll)
		protected.GET("/client/stop_all", clientStopAll)
		protected.GET("/client/restart_all", clientRestartAll)
		protected.GET("/client/edit/:name", clientEditForm)
		protected.POST("/client/edit/:name", clientEdit)
		protected.GET("/server/start/:name", serverStart)
		protected.GET("/server/stop/:name", serverStop)
		protected.GET("/server/restart/:name", serverRestart)
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

		// Legacy/Unused for now but kept for direct access if needed
		protected.POST("/install", installFRP)
		protected.GET("/client/logs/:name", clientLogs)
		protected.GET("/server/logs/:name", serverLogs)
		protected.GET("/efrp/logs", efrpLogs)
		protected.GET("/stop-all", stopAll)
		protected.GET("/remove", removeForm)
		protected.POST("/remove", removeFRP)
	}

	fmt.Println("Server starting on :5001...")
	r.Run(":5001")
}

// --- New/Updated Page Handlers ---

func setupFRPForm(c *gin.Context) {
	username, _ := c.Get("username")
	c.HTML(http.StatusOK, "setup-frp.html", gin.H{
		"Username": username,
	})
}

func manageFRP(c *gin.Context) {
	// Get clients
	clientFiles, _ := filepath.Glob(filepath.Join(ClientConfigDir, "*.toml"))
	var clientList []string
	for _, f := range clientFiles {
		name := strings.TrimSuffix(filepath.Base(f), ".toml")
		clientList = append(clientList, name)
	}

	// Get servers
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
		c.Redirect(http.StatusFound, "/settings?error="+url.QueryEscape("New Username and Current Password fields are required."))
		return
	}
	if newPassword != confirmPassword {
		c.Redirect(http.StatusFound, "/settings?error="+url.QueryEscape("New passwords do not match."))
		return
	}

	usersMutex.Lock()
	defer usersMutex.Unlock()

	user, exists := users[usernameStr]
	if !exists || !verifyPassword(currentPassword, user.PasswordHash) {
		c.Redirect(http.StatusFound, "/settings?error="+url.QueryEscape("Incorrect current password."))
		return
	}

	// Check if new username is taken by another user
	if newUsername != usernameStr {
		if _, userExists := users[newUsername]; userExists {
			c.Redirect(http.StatusFound, "/settings?error="+url.QueryEscape("New username is already taken."))
			return
		}
	}

	newPasswordHash := user.PasswordHash
	if newPassword != "" {
		newPasswordHash = hashPassword(newPassword)
	}

	// Create the updated user entry
	updatedUser := User{
		Username:     newUsername,
		PasswordHash: newPasswordHash,
	}

	// Remove old entry if username has changed, then add new one
	if newUsername != usernameStr {
		delete(users, usernameStr)
	}
	users[newUsername] = updatedUser

	if err := saveUsersToFileInternal(); err != nil {
		log.Println("Failed to save users:", err)
		c.Redirect(http.StatusFound, "/settings?error="+url.QueryEscape("Failed to save settings to file."))
		return
	}

	// Log the user out
	sessionID, _ := c.Cookie("frp-session")
	delete(sessions, sessionID)
	c.SetCookie("frp-session", "", -1, "/", "", false, true)

	c.Redirect(http.StatusFound, "/login?message="+url.QueryEscape("Settings updated. Please log in with your new credentials."))
}

// --- Feature Handlers & Logic ---

func recordNetworkHistory() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		info, err := getSystemInfo()
		if err != nil {
			log.Println("Error recording network history:", err)
			continue
		}

		historyMutex.Lock()
		networkHistory = append(networkHistory, NetworkDataPoint{
			Timestamp:       time.Now(),
			NetworkUpload:   info.NetworkUpload,
			NetworkDownload: info.NetworkDownload,
		})
		// Keep only the last 60 data points (5 minutes)
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
	status := FRPStatus{
		ClientList: make([]string, 0),
	}
	clientIDs := make(map[string]bool)
	proxyCount := 0

	// Find all running frps services
	output := runCmdOutput("systemctl", "list-units", "frps@*.service", "--state=running", "--no-pager", "--plain")
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.HasPrefix(fields[0], "frps@") {
			serviceName := fields[0]
			logOutput := runCmdOutput("journalctl", "-u", serviceName, "-n", "200", "--no-pager")

			// Regex to find client logins
			clientRegex := regexp.MustCompile(`\[([0-9a-f]{16})\] client login`)
			matches := clientRegex.FindAllStringSubmatch(logOutput, -1)
			for _, match := range matches {
				if len(match) > 1 {
					clientIDs[match[1]] = true
				}
			}

			// Count new proxies
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
	errorRegex := regexp.MustCompile(`(?i)(\[E\]|error|fail)`)
	if errorRegex.MatchString(logOutput) {
		return "error"
	}
	warningRegex := regexp.MustCompile(`(?i)(\[W\]|warn)`)
	if warningRegex.MatchString(logOutput) {
		return "warning"
	}
	return "running"
}

func connectionStatusHandler(c *gin.Context) {
	var clients []ConnectionStatus
	var servers []ConnectionStatus

	clientFiles, _ := filepath.Glob(filepath.Join(ClientConfigDir, "*.toml"))
	for _, f := range clientFiles {
		name := strings.TrimSuffix(filepath.Base(f), ".toml")
		status := getServiceStatus("frpc@" + name)
		clients = append(clients, ConnectionStatus{Name: name, Status: status})
	}

	serverFiles, _ := filepath.Glob(filepath.Join(ServerConfigDir, "*.toml"))
	for _, f := range serverFiles {
		name := strings.TrimSuffix(filepath.Base(f), ".toml")
		status := getServiceStatus("frps@" + name)
		servers = append(servers, ConnectionStatus{Name: name, Status: status})
	}

	c.JSON(http.StatusOK, gin.H{
		"clients": clients,
		"servers": servers,
	})
}

func streamLogs(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Println("Failed to upgrade connection:", err)
		return
	}
	defer conn.Close()

	logType := c.Param("type") // "client", "server", "efrp"
	name := c.Param("name")    // service name part

	var serviceName string
	switch logType {
	case "client":
		serviceName = "frpc@" + name
	case "server":
		serviceName = "frps@" + name
	case "efrp":
		serviceName = "EFRP.service"
	default:
		conn.WriteMessage(websocket.TextMessage, []byte("Invalid log type specified."))
		return
	}

	cmd := exec.Command("journalctl", "-f", "-u", serviceName, "-n", "20", "--no-pager")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Println("Failed to get stdout pipe:", err)
		return
	}

	if err := cmd.Start(); err != nil {
		log.Println("Failed to start log command:", err)
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if err := conn.WriteMessage(websocket.TextMessage, []byte(line)); err != nil {
			break // Client disconnected
		}
	}

	cmd.Process.Kill()
}

func loadPresets() {
	presetsMutex.Lock()
	defer presetsMutex.Unlock()

	file, err := ioutil.ReadFile(PresetsFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("Presets file not found, starting fresh.")
			presets = make(map[string]Preset)
		} else {
			log.Println("Error reading presets file:", err)
		}
		return
	}
	json.Unmarshal(file, &presets)
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "Preset name cannot be empty"})
		return
	}

	presets[preset.Name] = preset
	if err := savePresetsToFile(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save preset"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func deletePreset(c *gin.Context) {
	var data map[string]string
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	name := data["name"]
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Preset name not provided"})
		return
	}

	delete(presets, name)
	if err := savePresetsToFile(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete preset"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func loadServerPresets() {
	serverPresetsMutex.Lock()
	defer serverPresetsMutex.Unlock()

	file, err := ioutil.ReadFile(ServerPresetsFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("Server presets file not found, starting fresh.")
			serverPresets = make(map[string]ServerPreset)
		} else {
			log.Println("Error reading server presets file:", err)
		}
		return
	}
	json.Unmarshal(file, &serverPresets)
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid data: " + err.Error()})
		return
	}
	if preset.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Preset name cannot be empty"})
		return
	}

	serverPresets[preset.Name] = preset
	if err := saveServerPresetsToFile(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save server preset"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func deleteServerPreset(c *gin.Context) {
	var data map[string]string
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	name := data["name"]
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Preset name not provided"})
		return
	}

	delete(serverPresets, name)
	if err := saveServerPresetsToFile(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete server preset"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// --- Authentication & System Info ---

func saveUsersToFileInternal() error {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(UsersFile), 0755); err != nil {
		return err
	}
	return ioutil.WriteFile(UsersFile, data, 0644)
}

func saveUsers() error {
	usersMutex.Lock()
	defer usersMutex.Unlock()
	return saveUsersToFileInternal()
}

func loadUsers() {
	usersMutex.Lock()
	defer usersMutex.Unlock()

	file, err := ioutil.ReadFile(UsersFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("Users file not found, creating with default user.")
			users = map[string]User{
				"admin": {
					Username:     "admin",
					PasswordHash: "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918", // "admin" hashed
				},
			}
			if err := saveUsersToFileInternal(); err != nil {
				log.Fatal("Failed to create initial users file:", err)
			}
		} else {
			log.Fatal("Error reading users file:", err)
		}
		return
	}
	if err := json.Unmarshal(file, &users); err != nil {
		log.Fatal("Error unmarshalling users file:", err)
	}
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
	sessionID, err := c.Cookie("frp-session")
	if err == nil {
		if _, exists := sessions[sessionID]; exists {
			c.Redirect(http.StatusFound, "/")
			return
		}
	}
	c.HTML(http.StatusOK, "login.html", gin.H{
		"Error":   c.Query("error"),
		"Message": c.Query("message"),
	})
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
	sessionID, err := c.Cookie("frp-session")
	if err == nil {
		delete(sessions, sessionID)
	}
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

func getSystemInfo() (*SystemInfo, error) {
	// CPU usage calculation based on user and system time.
	t1, err := cpu.Times(false)
	if err != nil || len(t1) == 0 {
		return nil, err
	}
	// We need to get CPU times at two different points to calculate usage.
	time.Sleep(time.Second)
	t2, err := cpu.Times(false)
	if err != nil || len(t2) == 0 {
		return nil, err
	}

	t1_all := t1[0]
	t2_all := t2[0]

	// Calculate the total time delta by summing up all the time states.
	t1_total := t1_all.User + t1_all.System + t1_all.Idle + t1_all.Nice + t1_all.Iowait + t1_all.Irq + t1_all.Softirq + t1_all.Steal + t1_all.Guest + t1_all.GuestNice
	t2_total := t2_all.User + t2_all.System + t2_all.Idle + t2_all.Nice + t2_all.Iowait + t2_all.Irq + t2_all.Softirq + t2_all.Steal + t2_all.Guest + t2_all.GuestNice
	delta_total := t2_total - t1_total

	// Calculate the "active" time delta, which is only user and system time.
	delta_active := (t2_all.User - t1_all.User) + (t2_all.System - t1_all.System)

	var cpuUsage float64
	if delta_total > 0 {
		cpuUsage = delta_active / delta_total * 100.0
	} else {
		cpuUsage = 0.0 // Avoid division by zero
	}

	// Clamp the value between 0 and 100 to handle potential floating point inaccuracies or system quirks.
	if cpuUsage < 0 {
		cpuUsage = 0.0
	}
	if cpuUsage > 100.0 {
		cpuUsage = 100.0
	}

	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}
	netStats, err := net.IOCounters(false)
	if err != nil {
		return nil, err
	}

	var uploadSpeed, downloadSpeed uint64
	if len(netStats) > 0 {
		currentTime := time.Now()
		if len(lastNetStats) > 0 && !lastNetTime.IsZero() {
			timeDiff := currentTime.Sub(lastNetTime).Seconds()
			if timeDiff > 0 {
				var currentUpload, currentDownload, lastUpload, lastDownload uint64
				for _, stat := range netStats {
					currentUpload += stat.BytesSent
					currentDownload += stat.BytesRecv
				}
				for _, stat := range lastNetStats {
					lastUpload += stat.BytesSent
					lastDownload += stat.BytesRecv
				}
				uploadSpeed = uint64(float64(currentUpload-lastUpload) / timeDiff)
				downloadSpeed = uint64(float64(currentDownload-lastDownload) / timeDiff)
			}
		}
		lastNetStats = make(map[string]net.IOCountersStat)
		for _, stat := range netStats {
			lastNetStats[stat.Name] = stat
		}
		lastNetTime = currentTime
	}

	return &SystemInfo{
		CPUUsage:        cpuUsage,
		RAMUsed:         memInfo.Used,
		RAMTotal:        memInfo.Total,
		NetworkUpload:   uploadSpeed,
		NetworkDownload: downloadSpeed,
	}, nil
}

// --- Route Handlers ---

func home(c *gin.Context) {
	username, _ := c.Get("username")
	c.HTML(http.StatusOK, "home.html", gin.H{
		"Username": username,
	})
}

func installFRP(c *gin.Context) {
	optimize()
	arch := runtime.GOARCH
	if arch == "amd64" || arch == "arm64" {
		// ok
	} else if arch == "arm" || arch == "armv7l" || arch == "armv6l" {
		arch = "arm"
	} else {
		c.String(http.StatusBadRequest, "Unsupported architecture")
		return
	}
	osType := runtime.GOOS
	resp, err := http.Get("https://api.github.com/repos/fatedier/frp/releases/latest")
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	version := strings.TrimPrefix(strings.Split(string(body), `"tag_name":"`)[1], "v")
	version = strings.Split(version, `"`)[0]
	url := fmt.Sprintf("https://github.com/fatedier/frp/releases/download/v%s/frp_%s_%s_%s.tar.gz", version, version, osType, arch)
	resp, err = http.Get(url)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	defer resp.Body.Close()
	file, _ := ioutil.TempFile("", "frp.tar.gz")
	io.Copy(file, resp.Body)
	file.Close()

	gz, _ := os.Open(file.Name())
	defer gz.Close()
	gr, _ := gzip.NewReader(gz)
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if strings.HasSuffix(hdr.Name, "/frpc") || strings.Contains(hdr.Name, "/frpc") {
			out, _ := os.Create("/usr/local/bin/frpc")
			io.Copy(out, tr)
			out.Close()
			os.Chmod("/usr/local/bin/frpc", 0755)
		} else if strings.HasSuffix(hdr.Name, "/frps") || strings.Contains(hdr.Name, "/frps") {
			out, _ := os.Create("/usr/local/bin/frps")
			io.Copy(out, tr)
			out.Close()
			os.Chmod("/usr/local/bin/frps", 0755)
		}
	}

	os.MkdirAll(ClientConfigDir, 0755)
	os.MkdirAll(ServerConfigDir, 0755)
	os.MkdirAll(filepath.Dir(PresetsFile), 0755) // Ensure presets directory exists

	ioutil.WriteFile("/etc/systemd/system/frps@.service", []byte(`
[Unit]
Description=FRP Server Service (%i)
Documentation=https://gofrp.org/en/docs/overview/
After=network.target nss-lookup.target network-online.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=/usr/local/bin/frps -c /root/frp/server/%i.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
`), 0644)

	ioutil.WriteFile("/etc/systemd/system/frpc@.service", []byte(`
[Unit]
Description=FRP Client Service (%i)
Documentation=https://gofrp.org/en/docs/overview/
After=network.target nss-lookup.target network-online.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=/usr/local/bin/frpc -c /root/frp/client/%i.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
`), 0644)

	runCmd("systemctl", "daemon-reload")
	c.String(http.StatusOK, "FRP installed successfully")
}

func setupServer(c *gin.Context) {
	serverFormName := c.PostForm("server_name")
	if serverFormName == "" {
		c.String(http.StatusBadRequest, "Server Name cannot be empty.")
		return
	}
	// Sanitize the name for use in filenames and service names.
	reg := regexp.MustCompile("[^a-zA-Z0-9-]+")
	sanitizedName := reg.ReplaceAllString(strings.ReplaceAll(serverFormName, " ", "-"), "")
	if sanitizedName == "" {
		c.String(http.StatusBadRequest, "Invalid Server Name provided. Use alphanumeric characters and hyphens.")
		return
	}

	bindPort := c.PostForm("bind_port")
	if bindPort == "" {
		bindPort = "7000"
	}
	protoChoice := c.PostForm("proto_choice")
	if protoChoice == "" {
		protoChoice = "2"
	}
	useMux := c.PostForm("use_mux") == "true"
	token := c.PostForm("token")
	if token == "" {
		token = "mikeesierrah"
	}

	configPath := filepath.Join(ServerConfigDir, fmt.Sprintf("%s.toml", sanitizedName))
	if _, err := os.Stat(configPath); err == nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("A server with the name '%s' already exists.", sanitizedName))
		return
	}

	f, _ := os.Create(configPath)
	defer f.Close()
	fmt.Fprint(f, "# Auto-generated frps config\n")
	fmt.Fprint(f, "bindAddr = \"::\"\n")
	fmt.Fprintf(f, "bindPort = %s\n", bindPort)
	if protoChoice == "2" {
		fmt.Fprintf(f, "quicBindPort = %s\n", bindPort)
		fmt.Fprint(f, "transport.quic.keepalivePeriod = 10\n")
		fmt.Fprint(f, "transport.quic.maxIdleTimeout = 30\n")
		fmt.Fprint(f, "transport.quic.maxIncomingStreams = 100000\n")
	} else if protoChoice == "3" {
		fmt.Fprintf(f, "kcpBindPort = %s\n", bindPort)
	}
	fmt.Fprint(f, "transport.heartbeatTimeout = 90\n")
	fmt.Fprint(f, "transport.maxPoolCount = 65535\n")
	fmt.Fprintf(f, "transport.tcpMux = %t\n", useMux)
	fmt.Fprint(f, "transport.tcpMuxKeepaliveInterval = 10\n")
	fmt.Fprint(f, "transport.tcpKeepalive = 120\n")
	fmt.Fprint(f, "auth.method = \"token\"\n")
	fmt.Fprintf(f, "auth.token = \"%s\"\n", token)

	serviceName := fmt.Sprintf("frps@%s", sanitizedName)
	runCmd("systemctl", "enable", "--now", serviceName)
	c.Redirect(http.StatusFound, "/manage-frp")
}

func setupClient(c *gin.Context) {
	clientName := c.PostForm("client_name")
	if clientName == "" {
		c.String(http.StatusBadRequest, "Client Name cannot be empty.")
		return
	}
	// Sanitize the name for use in filenames and service names.
	reg := regexp.MustCompile("[^a-zA-Z0-9-]+")
	sanitizedName := reg.ReplaceAllString(strings.ReplaceAll(clientName, " ", "-"), "")
	if sanitizedName == "" {
		c.String(http.StatusBadRequest, "Invalid Client Name provided. Use alphanumeric characters and hyphens.")
		return
	}

	serverIP := c.PostForm("server_ip")
	serverPort := c.PostForm("server_port")
	if serverPort == "" {
		serverPort = "7000"
	}
	authToken := c.PostForm("auth_token")
	if authToken == "" {
		authToken = "mikeesierrah"
	}
	transport := c.PostForm("transport")
	if transport == "" {
		transport = "tcp"
	}
	useMux := c.PostForm("use_mux") == "true"
	portInput := c.PostForm("port_input")
	ports := parsePorts(portInput)

	configName := fmt.Sprintf("%s.toml", sanitizedName)
	configPath := filepath.Join(ClientConfigDir, configName)
	if _, err := os.Stat(configPath); err == nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("A client with the name '%s' already exists.", sanitizedName))
		return
	}

	f, _ := os.Create(configPath)
	defer f.Close()
	fmt.Fprintf(f, "serverAddr = \"%s\"\n", serverIP)
	fmt.Fprintf(f, "serverPort = %s\n", serverPort)
	fmt.Fprint(f, "loginFailExit = false\n")
	fmt.Fprint(f, "auth.method = \"token\"\n")
	fmt.Fprintf(f, "auth.token = \"%s\"\n", authToken)
	fmt.Fprintf(f, "transport.protocol = \"%s\"\n", transport)
	fmt.Fprintf(f, "transport.tcpMux = %t\n", useMux)
	fmt.Fprint(f, "transport.tcpMuxKeepaliveInterval = 10\n")
	fmt.Fprint(f, "transport.dialServerTimeout = 10\n")
	fmt.Fprint(f, "transport.dialServerKeepalive = 120\n")
	fmt.Fprint(f, "transport.poolCount = 20\n")
	fmt.Fprint(f, "transport.heartbeatInterval = 30\n")
	fmt.Fprint(f, "transport.heartbeatTimeout = 90\n")
	fmt.Fprint(f, "transport.tls.enable = false\n")
	fmt.Fprint(f, "transport.quic.keepalivePeriod = 10\n")
	fmt.Fprint(f, "transport.quic.maxIdleTimeout = 30\n")
	fmt.Fprint(f, "transport.quic.maxIncomingStreams = 100000\n")
	for _, port := range ports {
		fmt.Fprint(f, "\n[[proxies]]\n")
		fmt.Fprintf(f, "name = \"tcp-%d\"\n", port)
		fmt.Fprint(f, "type = \"tcp\"\n")
		fmt.Fprint(f, "localIP = \"127.0.0.1\"\n")
		fmt.Fprintf(f, "localPort = %d\n", port)
		fmt.Fprintf(f, "remotePort = %d\n", port)
		fmt.Fprint(f, "transport.useEncryption = false\n")
		fmt.Fprint(f, "transport.useCompression = true\n")
	}

	serviceName := fmt.Sprintf("frpc@%s", sanitizedName)
	runCmd("systemctl", "enable", "--now", serviceName)
	c.Redirect(http.StatusFound, "/manage-frp")
}

func clientStart(c *gin.Context) {
	name := c.Param("name")
	runCmd("systemctl", "start", "frpc@"+name)
	redirectURL := fmt.Sprintf("/manage-frp#clients:%s", name)
	c.Redirect(http.StatusFound, redirectURL)
}

func clientStop(c *gin.Context) {
	name := c.Param("name")
	runCmd("systemctl", "stop", "frpc@"+name)
	redirectURL := fmt.Sprintf("/manage-frp#clients:%s", name)
	c.Redirect(http.StatusFound, redirectURL)
}

func clientRestart(c *gin.Context) {
	name := c.Param("name")
	runCmd("systemctl", "restart", "frpc@"+name)
	redirectURL := fmt.Sprintf("/manage-frp#clients:%s", name)
	c.Redirect(http.StatusFound, redirectURL)
}

func clientStartAll(c *gin.Context) {
	files, _ := filepath.Glob(filepath.Join(ClientConfigDir, "*.toml"))
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".toml")
		runCmd("systemctl", "start", "frpc@"+name)
	}
	c.Redirect(http.StatusFound, "/manage-frp#clients")
}

func clientStopAll(c *gin.Context) {
	files, _ := filepath.Glob(filepath.Join(ClientConfigDir, "*.toml"))
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".toml")
		runCmd("systemctl", "stop", "frpc@"+name)
	}
	c.Redirect(http.StatusFound, "/manage-frp#clients")
}

func clientRestartAll(c *gin.Context) {
	files, _ := filepath.Glob(filepath.Join(ClientConfigDir, "*.toml"))
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".toml")
		runCmd("systemctl", "restart", "frpc@"+name)
	}
	c.Redirect(http.StatusFound, "/manage-frp#clients")
}

func clientLogs(c *gin.Context) {
	name := c.Param("name")
	lines := c.Query("lines")
	if lines == "" {
		lines = "10"
	}
	log := runCmdOutput("journalctl", "-u", "frpc@"+name, "-n", lines, "--no-pager")
	c.HTML(http.StatusOK, "logs.html", gin.H{"Log": log, "Back": "/manage-frp"})
}

func clientEditForm(c *gin.Context) {
	name := c.Param("name")
	path := filepath.Join(ClientConfigDir, name+".toml")
	content, _ := ioutil.ReadFile(path)
	c.HTML(http.StatusOK, "edit.html", gin.H{"Content": string(content), "Name": name, "Type": "client"})
}

func clientEdit(c *gin.Context) {
	oldName := c.Param("name")
	content := c.PostForm("content")
	newName := c.PostForm("name") // The new name from the form

	// Sanitize the new name for use in filenames and service names.
	reg := regexp.MustCompile("[^a-zA-Z0-9-]+")
	sanitizedNewName := reg.ReplaceAllString(strings.ReplaceAll(newName, " ", "-"), "")
	if sanitizedNewName == "" {
		c.String(http.StatusBadRequest, "Invalid new name provided. Use alphanumeric characters and hyphens.")
		return
	}

	// If the name hasn't changed, perform a simple update.
	if oldName == sanitizedNewName {
		path := filepath.Join(ClientConfigDir, oldName+".toml")
		ioutil.WriteFile(path, []byte(content), 0644)
		if isActive("frpc@" + oldName) {
			runCmd("systemctl", "restart", "frpc@"+oldName)
		}
		redirectURL := fmt.Sprintf("/manage-frp#clients:%s", oldName)
		c.Redirect(http.StatusFound, redirectURL)
		return
	}

	// --- Name has changed, perform the rename logic ---
	oldPath := filepath.Join(ClientConfigDir, oldName+".toml")
	newPath := filepath.Join(ClientConfigDir, sanitizedNewName+".toml")

	// 1. Check if a config with the new name already exists to prevent overwriting.
	if _, err := os.Stat(newPath); err == nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("A client configuration named '%s' already exists.", sanitizedNewName))
		return
	}

	// 2. Stop and disable the old service.
	wasActive := isActive("frpc@" + oldName)
	if wasActive {
		runCmd("systemctl", "stop", "frpc@"+oldName)
	}
	runCmd("systemctl", "disable", "frpc@"+oldName)

	// 3. Rename the configuration file.
	if err := os.Rename(oldPath, newPath); err != nil {
		log.Printf("Error renaming client config file: %v", err)
		// Try to revert the service state change if file rename fails.
		runCmd("systemctl", "enable", "frpc@"+oldName)
		if wasActive {
			runCmd("systemctl", "start", "frpc@"+oldName)
		}
		c.String(http.StatusInternalServerError, "Failed to rename configuration file.")
		return
	}

	// 4. Write the new/updated content to the newly named file.
	ioutil.WriteFile(newPath, []byte(content), 0644)

	// 5. Enable and, if it was active before, start the new service.
	runCmd("systemctl", "enable", "frpc@"+sanitizedNewName)
	if wasActive {
		runCmd("systemctl", "start", "frpc@"+sanitizedNewName)
	}

	// 6. Redirect to the manage page with the new name selected.
	redirectURL := fmt.Sprintf("/manage-frp#clients:%s", sanitizedNewName)
	c.Redirect(http.StatusFound, redirectURL)
}

func serverStart(c *gin.Context) {
	name := c.Param("name")
	runCmd("systemctl", "start", "frps@"+name)
	redirectURL := fmt.Sprintf("/manage-frp#servers:%s", name)
	c.Redirect(http.StatusFound, redirectURL)
}

func serverStop(c *gin.Context) {
	name := c.Param("name")
	runCmd("systemctl", "stop", "frps@"+name)
	redirectURL := fmt.Sprintf("/manage-frp#servers:%s", name)
	c.Redirect(http.StatusFound, redirectURL)
}

func serverRestart(c *gin.Context) {
	name := c.Param("name")
	runCmd("systemctl", "restart", "frps@"+name)
	redirectURL := fmt.Sprintf("/manage-frp#servers:%s", name)
	c.Redirect(http.StatusFound, redirectURL)
}

func serverStartAll(c *gin.Context) {
	files, _ := filepath.Glob(filepath.Join(ServerConfigDir, "*.toml"))
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".toml")
		runCmd("systemctl", "start", "frps@"+name)
	}
	c.Redirect(http.StatusFound, "/manage-frp#servers")
}

func serverStopAll(c *gin.Context) {
	files, _ := filepath.Glob(filepath.Join(ServerConfigDir, "*.toml"))
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".toml")
		runCmd("systemctl", "stop", "frps@"+name)
	}
	c.Redirect(http.StatusFound, "/manage-frp#servers")
}

func serverRestartAll(c *gin.Context) {
	files, _ := filepath.Glob(filepath.Join(ServerConfigDir, "*.toml"))
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".toml")
		runCmd("systemctl", "restart", "frps@"+name)
	}
	c.Redirect(http.StatusFound, "/manage-frp#servers")
}

func serverLogs(c *gin.Context) {
	name := c.Param("name")
	lines := c.Query("lines")
	if lines == "" {
		lines = "10"
	}
	log := runCmdOutput("journalctl", "-u", "frps@"+name, "-n", lines, "--no-pager")
	c.HTML(http.StatusOK, "logs.html", gin.H{"Log": log, "Back": "/manage-frp"})
}

func serverEditForm(c *gin.Context) {
	name := c.Param("name")
	path := filepath.Join(ServerConfigDir, name+".toml")
	content, _ := ioutil.ReadFile(path)
	c.HTML(http.StatusOK, "edit.html", gin.H{"Content": string(content), "Name": name, "Type": "server"})
}

func serverEdit(c *gin.Context) {
	oldName := c.Param("name")
	content := c.PostForm("content")
	newName := c.PostForm("name") // The new name from the form

	// Sanitize the new name for use in filenames and service names.
	reg := regexp.MustCompile("[^a-zA-Z0-9-]+")
	sanitizedNewName := reg.ReplaceAllString(strings.ReplaceAll(newName, " ", "-"), "")
	if sanitizedNewName == "" {
		c.String(http.StatusBadRequest, "Invalid new name provided. Use alphanumeric characters and hyphens.")
		return
	}

	// If the name hasn't changed, perform a simple update.
	if oldName == sanitizedNewName {
		path := filepath.Join(ServerConfigDir, oldName+".toml")
		ioutil.WriteFile(path, []byte(content), 0644)
		if isActive("frps@" + oldName) {
			runCmd("systemctl", "restart", "frps@"+oldName)
		}
		redirectURL := fmt.Sprintf("/manage-frp#servers:%s", oldName)
		c.Redirect(http.StatusFound, redirectURL)
		return
	}

	// --- Name has changed, perform the rename logic ---
	oldPath := filepath.Join(ServerConfigDir, oldName+".toml")
	newPath := filepath.Join(ServerConfigDir, sanitizedNewName+".toml")

	// 1. Check if a config with the new name already exists to prevent overwriting.
	if _, err := os.Stat(newPath); err == nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("A server configuration named '%s' already exists.", sanitizedNewName))
		return
	}

	// 2. Stop and disable the old service.
	wasActive := isActive("frps@" + oldName)
	if wasActive {
		runCmd("systemctl", "stop", "frps@"+oldName)
	}
	runCmd("systemctl", "disable", "frps@"+oldName)

	// 3. Rename the configuration file.
	if err := os.Rename(oldPath, newPath); err != nil {
		log.Printf("Error renaming server config file: %v", err)
		// Try to revert the service state change if file rename fails.
		runCmd("systemctl", "enable", "frps@"+oldName)
		if wasActive {
			runCmd("systemctl", "start", "frps@"+oldName)
		}
		c.String(http.StatusInternalServerError, "Failed to rename configuration file.")
		return
	}

	// 4. Write the new/updated content to the newly named file.
	ioutil.WriteFile(newPath, []byte(content), 0644)

	// 5. Enable and, if it was active before, start the new service.
	runCmd("systemctl", "enable", "frps@"+sanitizedNewName)
	if wasActive {
		runCmd("systemctl", "start", "frps@"+sanitizedNewName)
	}

	// 6. Redirect to the manage page with the new name selected.
	redirectURL := fmt.Sprintf("/manage-frp#servers:%s", sanitizedNewName)
	c.Redirect(http.StatusFound, redirectURL)
}

func efrp(c *gin.Context) {
	c.HTML(http.StatusOK, "efrp.html", nil)
}

func efrpStart(c *gin.Context) {
	runCmd("systemctl", "enable", "--now", "EFRP.service")
	c.Redirect(http.StatusFound, "/efrp")
}

func efrpStop(c *gin.Context) {
	runCmd("systemctl", "disable", "--now", "EFRP.service")
	c.Redirect(http.StatusFound, "/efrp")
}

func efrpLogs(c *gin.Context) {
	lines := c.Query("lines")
	if lines == "" {
		lines = "10"
	}
	log := runCmdOutput("journalctl", "-u", "EFRP.service", "-n", lines, "--no-pager")
	c.HTML(http.StatusOK, "logs.html", gin.H{"Log": log, "Back": "/efrp"})
}

func showStatus(c *gin.Context) {
	version := runCmdOutput("/usr/local/bin/frps", "--version")
	if version == "" {
		version = "Not installed"
	}
	running := runCmdOutput("systemctl", "list-units", "--type=service", "--state=running")
	running = grep(running, "frp[sc]@")
	if running == "" {
		running = "None"
	}
	enabled := runCmdOutput("systemctl", "list-unit-files")
	enabled = grep(enabled, "frp[sc]@.*enabled")
	if enabled == "" {
		enabled = "None"
	}
	serverConfigs := runCmdOutput("ls", "-la", ServerConfigDir)
	if serverConfigs == "" {
		serverConfigs = "None"
	}
	clientConfigs := runCmdOutput("ls", "-la", ClientConfigDir)
	if clientConfigs == "" {
		clientConfigs = "None"
	}
	c.HTML(http.StatusOK, "status.html", gin.H{
		"Version":       version,
		"Running":       running,
		"Enabled":       enabled,
		"ServerConfigs": serverConfigs,
		"ClientConfigs": clientConfigs,
	})
}

func stopAll(c *gin.Context) {
	running := runCmdOutput("systemctl", "list-units", "--type=service", "--state=running")
	for _, line := range strings.Split(running, "\n") {
		if strings.Contains(line, "frps@") || strings.Contains(line, "frpc@") {
			service := strings.Fields(line)[0]
			runCmd("systemctl", "stop", service)
		}
	}
	c.HTML(http.StatusOK, "message.html", gin.H{"Message": "All services stopped", "Back": "/"})
}

func removeForm(c *gin.Context) {
	c.HTML(http.StatusOK, "remove.html", nil)
}

func removeFRP(c *gin.Context) {
	running := runCmdOutput("systemctl", "list-units", "--type=service", "--state=running")
	for _, line := range strings.Split(running, "\n") {
		if strings.Contains(line, "frps@") || strings.Contains(line, "frpc@") {
			service := strings.Fields(line)[0]
			runCmd("systemctl", "stop", service)
		}
	}
	enabled := runCmdOutput("systemctl", "list-unit-files")
	for _, line := range strings.Split(enabled, "\n") {
		if strings.Contains(line, "frps@") || strings.Contains(line, "frpc@") {
			service := strings.Fields(line)[0]
			runCmd("systemctl", "disable", service)
		}
	}
	os.Remove("/etc/systemd/system/frps@.service")
	os.Remove("/etc/systemd/system/frpc@.service")
	os.Remove("/usr/local/bin/frpc")
	os.Remove("/usr/local/bin/frps")
	os.RemoveAll("/root/frp/")
	runCmd("systemctl", "daemon-reload")
	c.String(http.StatusOK, "FRP removed successfully")
}

// --- Utility Functions ---

func optimize() {
	cronJob := "0 */3 * * * pkill -10 -x frpc; pkill -10 -x frps"
	crons := runCmdOutput("crontab", "-l")
	if !strings.Contains(crons, cronJob) {
		runCmd("bash", "-c", fmt.Sprintf("(crontab -l 2>/dev/null; echo '%s') | crontab -", cronJob))
	}
	if runCmdOutput("sysctl", "-n", "net.core.default_qdisc") == "fq" && runCmdOutput("sysctl", "-n", "net.ipv4.tcp_congestion_control") == "bbr" {
		return
	}
	ioutil.WriteFile("/etc/sysctl.conf", []byte("net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n"), 0644)
	ioutil.WriteFile("/etc/modules-load.d/bbr.conf", []byte("tcp_bbr\n"), 0644)
	runCmd("modprobe", "tcp_bbr")
	runCmd("sysctl", "-p")
}

func parsePorts(input string) []int {
	var ports []int
	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			parts := strings.Split(part, "-")
			start, _ := strconv.Atoi(parts[0])
			end, _ := strconv.Atoi(parts[1])
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			p, _ := strconv.Atoi(part)
			ports = append(ports, p)
		}
	}
	return ports
}

func runCmd(cmd ...string) {
	exec.Command(cmd[0], cmd[1:]...).Run()
}

func runCmdOutput(cmd ...string) string {
	out, _ := exec.Command(cmd[0], cmd[1:]...).Output()
	return strings.TrimSpace(string(out))
}

func isActive(service string) bool {
	out, _ := exec.Command("systemctl", "is-active", service).Output()
	return strings.TrimSpace(string(out)) == "active"
}

func grep(input, pattern string) string {
	var result strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(input))
	for scanner.Scan() {
		line := scanner.Text()
		match, _ := regexp.MatchString(pattern, line)
		if match {
			result.WriteString(line + "\n")
		}
	}
	return result.String()
}
