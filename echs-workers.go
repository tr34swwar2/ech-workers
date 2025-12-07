package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ======================== 配置结构体 & 全局参数 ========================

// InstanceConfig 代理实例配置
type InstanceConfig struct {
	ListenAddr string `json:"listen_addr"`
	ServerAddr string `json:"server_addr"`
	ServerIP   string `json:"server_ip"`
	Token      string `json:"token"`
	DnsServer  string `json:"dns_server"`
	EchDomain  string `json:"ech_domain"`
	ProxyIP    string `json:"proxy_ip"`

	// 运行时 ECH 数据
	EchList   []byte
	EchListMu sync.RWMutex
}

var (
	configFile string           // 配置文件路径
	configs    []*InstanceConfig // 存储所有解析后的配置
)

func init() {
	// 仅保留配置文件路径标志
	flag.StringVar(&configFile, "c", "", "配置文件路径 (例如: config.json)。必须指定此参数。")
}

// loadConfig 函数用于加载和解析 JSON 配置文件
func loadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取文件失败: %w", err)
	}

	err = json.Unmarshal(data, &configs)
	if err != nil {
		return fmt.Errorf("解析 JSON 失败: %w", err)
	}
	
	// 校验配置并设置默认值
	for i, cfg := range configs {
		if cfg.ListenAddr == "" || cfg.ServerAddr == "" || cfg.Token == "" {
			return fmt.Errorf("实例 %d 配置不完整: 缺少 listen_addr, server_addr 或 token", i+1)
		}
		if cfg.DnsServer == "" {
			cfg.DnsServer = "dns.alidns.com/dns-query"
		}
		if cfg.EchDomain == "" {
			cfg.EchDomain = "cloudflare-ech.com"
		}
	}
	return nil
}

func main() {
	flag.Parse()

	// 强制要求使用配置文件
	if configFile == "" {
		log.Fatal("❌ 必须使用 -c 参数指定配置文件路径 (例如: -c config.json)")
	}

	// --- 配置文件模式 ---
	log.Printf("🚀 正在加载配置文件: %s", configFile)
	if err := loadConfig(configFile); err != nil {
		log.Fatalf("❌ 加载配置文件失败: %v", err)
	}

	if len(configs) == 0 {
		log.Fatal("❌ 未找到任何代理实例配置，请检查配置文件内容")
	}

	// 启动所有实例
	var wg sync.WaitGroup
	for i, cfg := range configs {
		wg.Add(1)
		go func(instance *InstanceConfig, index int) {
			defer wg.Done()
			log.Printf("🔌 [实例 %d / %s] 正在获取 ECH 配置...", index+1, instance.ListenAddr)
			if err := instance.prepareECH(); err != nil {
				// ECH 配置失败，直接退出该实例的启动
				log.Fatalf("❌ [实例 %d / %s] 获取 ECH 配置失败: %v", index+1, instance.ListenAddr, err)
			}
			instance.runProxyServer()
		}(cfg, i)
	}

	wg.Wait()
}

// ======================== 工具函数 (保持不变) ========================

func isNormalCloseError(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "normal closure")
}

// ======================== ECH 支持 (InstanceConfig 方法) ========================

const typeHTTPS = 65

// prepareECH 现在是 InstanceConfig 的方法
func (cfg *InstanceConfig) prepareECH() error {
	echBase64, err := cfg.queryHTTPSRecord()
	if err != nil {
		return fmt.Errorf("DNS 查询失败: %w", err)
	}
	if echBase64 == "" {
		return errors.New("未找到 ECH 参数")
	}
	raw, err := base64.StdEncoding.DecodeString(echBase64)
	if err != nil {
		return fmt.Errorf("ECH 解码失败: %w", err)
	}
	cfg.EchListMu.Lock()
	cfg.EchList = raw
	cfg.EchListMu.Unlock()
	log.Printf("✅ [%s ECH] 配置已加载，长度: %d 字节", cfg.ListenAddr, len(raw))
	return nil
}

// refreshECH 现在是 InstanceConfig 的方法
func (cfg *InstanceConfig) refreshECH() error {
	log.Printf("🔄 [%s ECH] 刷新配置...", cfg.ListenAddr)
	return cfg.prepareECH()
}

// getECHList 现在是 InstanceConfig 的方法
func (cfg *InstanceConfig) getECHList() ([]byte, error) {
	cfg.EchListMu.RLock()
	defer cfg.EchListMu.RUnlock()
	if len(cfg.EchList) == 0 {
		return nil, errors.New("ECH 配置未加载")
	}
	return cfg.EchList, nil
}

func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("加载系统根证书失败: %w", err)
	}
	return &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     serverName,
		EncryptedClientHelloConfigList: echList,
		EncryptedClientHelloRejectionVerify: func(cs tls.ConnectionState) error {
			return errors.New("服务器拒绝 ECH")
		},
		RootCAs: roots,
	}, nil
}

// queryHTTPSRecord 现在是 InstanceConfig 的方法
func (cfg *InstanceConfig) queryHTTPSRecord() (string, error) {
	dohURL := cfg.DnsServer
	if !strings.HasPrefix(dohURL, "https://") && !strings.HasPrefix(dohURL, "http://") {
		dohURL = "https://" + dohURL
	}
	return queryDoH(cfg.EchDomain, dohURL, cfg.ServerIP)
}

// queryDoH 执行 DoH 查询（包含 DNS 故障时的 IP 拨号回退逻辑）
func queryDoH(domain, dohURL string, serverFallbackIP string) (string, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", fmt.Errorf("无效的 DoH URL: %v", err)
	}

	dnsQuery := buildDNSQuery(domain, typeHTTPS)
	dnsBase64 := base64.RawURLEncoding.EncodeToString(dnsQuery)

	q := u.Query()
	q.Set("dns", dnsBase64)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	// 为 HTTP 客户端添加自定义 DialContext 来绕过系统 DNS (修复 127.0.0.1:53 报错)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: func() *x509.CertPool {
				pool, _ := x509.SystemCertPool()
				return pool
			}(),
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 10 * time.Second}
			
			// 1. 尝试使用系统 DNS 拨号
			conn, err := dialer.DialContext(ctx, network, addr)
			if err == nil {
				return conn, nil // 成功
			}

			// 2. 如果失败，尝试使用硬编码 IP 绕过系统 DNS
			dohHost, dohPort, splitErr := net.SplitHostPort(addr)
			if splitErr != nil {
				dohHost = addr
				dohPort = "443"
			}
			
			fallbackIP := serverFallbackIP 
			if fallbackIP == "" {
				fallbackIP = "1.1.1.1" 
			}

			log.Printf("[ECH Fetch DNS] 系统解析 %s 失败 (%v)。尝试使用 IP %s:%s 拨号...", dohHost, err, fallbackIP, dohPort)

			// 尝试使用 Fallback IP 拨号
			return dialer.DialContext(ctx, network, net.JoinHostPort(fallbackIP, dohPort))
		},
	}
	
	client := &http.Client{
		Transport: transport,
		Timeout: 15 * time.Second,
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("DoH 请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH 服务器返回错误: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取 DoH 响应失败: %v", err)
	}

	return parseDNSResponse(body)
}

func buildDNSQuery(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 512)
	query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return query
}

func parseDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", errors.New("响应过短")
	}
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", errors.New("无应答记录")
	}

	offset := 12
	for offset < len(response) && response[offset] != 0 {
		offset += int(response[offset]) + 1
	}
	offset += 5

	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) {
			break
		}
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}
		if offset+10 > len(response) {
			break
		}
		rrType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8
		dataLen := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		if offset+int(dataLen) > len(response) {
			break
		}
		data := response[offset : offset+int(dataLen)]
		offset += int(dataLen)

		if rrType == typeHTTPS {
			if ech := parseHTTPSRecord(data); ech != "" {
				return ech, nil
			}
		}
	}
	return "", nil
}

func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	offset := 2
	if offset >= len(data) {
		return ""
	}
	if data[offset] == 0 {
		offset++
	} else {
		for offset < len(data) && data[offset] != 0 {
			step := int(data[offset]) + 1
			if step <= 0 || offset+step > len(data) {
				return ""
			}
			offset += step
		}
		offset++
	}
	for offset+4 <= len(data) {
		if offset+4 > len(data) {
			return ""
		}
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if length == 0 || offset+int(length) > len(data) {
			break
		}
		value := data[offset : offset+int(length)]
		offset += int(length)
		if key == 5 {
			return base64.StdEncoding.EncodeToString(value)
		}
	}
	return ""
}

// ======================== DoH 代理支持 (InstanceConfig 方法) ========================

// queryDoHForProxy 现在是 InstanceConfig 的方法
func (cfg *InstanceConfig) queryDoHForProxy(dnsQuery []byte) ([]byte, error) {
	_, port, _, err := parseServerAddr(cfg.ServerAddr)
	if err != nil {
		return nil, err
	}

	// 构建 DoH URL
	dohURL := fmt.Sprintf("https://cloudflare-dns.com:%s/dns-query", port)

	echBytes, err := cfg.getECHList()
	if err != nil {
		return nil, fmt.Errorf("获取 ECH 配置失败: %w", err)
	}

	tlsCfg, err := buildTLSConfigWithECH("cloudflare-dns.com", echBytes)
	if err != nil {
		return nil, fmt.Errorf("构建 TLS 配置失败: %w", err)
	}

	// 创建 HTTP 客户端
	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
	}

	// 如果指定了 IP，使用自定义 Dialer
	if cfg.ServerIP != "" {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			dialer := &net.Dialer{
				Timeout: 10 * time.Second,
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(cfg.ServerIP, port))
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// 发送 DoH 请求
	req, err := http.NewRequest("POST", dohURL, bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH 响应错误: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// ======================== WebSocket 客户端 (InstanceConfig 方法) ========================

func parseServerAddr(addr string) (host, port, path string, err error) {
	if addr == "" {
		return "", "", "", errors.New("服务器地址为空")
	}
	path = "/"
	slashIdx := strings.Index(addr, "/")
	if slashIdx != -1 {
		if slashIdx < len(addr) {
			path = addr[slashIdx:]
		}
		addr = addr[:slashIdx]
	}
	if addr == "" {
		return "", "", "", errors.New("服务器地址格式错误")
	}
	host, port, err = net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return "", "", "", fmt.Errorf("无效的服务器地址格式: %v", err)
	}
	return host, port, path, nil
}

// dialWebSocketWithECH 现在是 InstanceConfig 的方法
func (cfg *InstanceConfig) dialWebSocketWithECH(maxRetries int) (*websocket.Conn, error) {
	host, port, path, err := parseServerAddr(cfg.ServerAddr)
	if err != nil {
		return nil, err
	}

	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)

	for attempt := 1; attempt <= maxRetries; attempt++ {
		echBytes, echErr := cfg.getECHList()
		if echErr != nil {
			if attempt < maxRetries {
				cfg.refreshECH()
				continue
			}
			return nil, echErr
		}

		tlsCfg, tlsErr := buildTLSConfigWithECH(host, echBytes)
		if tlsErr != nil {
			return nil, tlsErr
		}

		dialer := websocket.Dialer{
			TLSClientConfig: tlsCfg,
			Subprotocols: func() []string {
				if cfg.Token == "" {
					return nil
				}
				return []string{cfg.Token} // 使用 cfg.Token
			}(),
			HandshakeTimeout: 10 * time.Second,
		}

		if cfg.ServerIP != "" {
			dialer.NetDial = func(network, address string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				//支持优选(非标端口), IPv6 支持
				ipHost := cfg.ServerIP
				userHost, userPort, splitErr := net.SplitHostPort(cfg.ServerIP)
				if splitErr == nil {
					ipHost = userHost
					port = userPort
				}
				return net.DialTimeout(network, net.JoinHostPort(ipHost, port), 10*time.Second)
			}
		}

		wsConn, _, dialErr := dialer.Dial(wsURL, nil)
		if dialErr != nil {
			if strings.Contains(dialErr.Error(), "ECH") && attempt < maxRetries {
				log.Printf("⚠️ [%s ECH] 连接失败，尝试刷新配置 (%d/%d)", cfg.ListenAddr, attempt, maxRetries)
				cfg.refreshECH()
				time.Sleep(time.Second)
				continue
			}
			return nil, dialErr
		}

		return wsConn, nil
	}

	return nil, errors.New("连接失败，已达最大重试次数")
}

// ======================== 统一代理服务器 (InstanceConfig 方法) ========================

// runProxyServer 现在是 InstanceConfig 的方法
func (cfg *InstanceConfig) runProxyServer() {
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("❌ [代理 / %s] 监听失败: %v", cfg.ListenAddr, err)
	}
	defer listener.Close()

	log.Printf("✅ [代理 / %s] 服务器启动: %s (支持 SOCKS5 和 HTTP)", cfg.ListenAddr, cfg.ListenAddr)
	log.Printf("   [代理 / %s] 后端: %s | Token: %s", cfg.ListenAddr, cfg.ServerAddr, cfg.Token)
	if cfg.ServerIP != "" {
		log.Printf("   [代理 / %s] 固定 IP: %s", cfg.ListenAddr, cfg.ServerIP)
	}
	if cfg.ProxyIP != "" {
		log.Printf("   [代理 / %s] 回退代理 IP: %s", cfg.ListenAddr, cfg.ProxyIP)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("⚠️ [代理 / %s] 接受连接失败: %v", cfg.ListenAddr, err)
			continue
		}

		go cfg.handleConnection(conn) // 调用 cfg.handleConnection
	}
}

// handleConnection 现在是 InstanceConfig 的方法
func (cfg *InstanceConfig) handleConnection(conn net.Conn) {
	if conn == nil {
		return
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	clientAddr := conn.RemoteAddr().String()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// 读取第一个字节判断协议
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}

	firstByte := buf[0]

	// 使用 switch 判断协议类型
	switch firstByte {
	case 0x05:
		// SOCKS5 协议
		cfg.handleSOCKS5(conn, clientAddr, firstByte)
	case 'C', 'G', 'P', 'H', 'D', 'O', 'T':
		// HTTP 协议 (CONNECT, GET, POST, HEAD, DELETE, OPTIONS, TRACE, PUT, PATCH)
		cfg.handleHTTP(conn, clientAddr, firstByte)
	default:
		log.Printf("[代理 / %s] %s 未知协议: 0x%02x", cfg.ListenAddr, clientAddr, firstByte)
	}
}

// ======================== SOCKS5 处理 (InstanceConfig 方法) ========================

// handleSOCKS5 现在是 InstanceConfig 的方法
func (cfg *InstanceConfig) handleSOCKS5(conn net.Conn, clientAddr string, firstByte byte) {
	if conn == nil {
		return
	}

	// 验证版本
	if firstByte != 0x05 {
		log.Printf("[SOCKS5 / %s] %s 版本错误: 0x%02x", cfg.ListenAddr, clientAddr, firstByte)
		return
	}
	
	// 读取认证方法数量
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	nmethods := buf[0]
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// 响应无需认证
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 读取请求
	buf = make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	if buf[0] != 5 {
		return
	}

	command := buf[1]
	atyp := buf[3]

	var host string
	switch atyp {
	case 0x01: // IPv4
		buf = make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		host = net.IP(buf).String()

	case 0x03: // 域名
		buf = make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		domainBuf := make([]byte, buf[0])
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return
		}
		host = string(domainBuf)

	case 0x04: // IPv6
		buf = make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		host = net.IP(buf).String()

	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	// 读取端口
	buf = make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	port := int(buf[0])<<8 | int(buf[1])

	switch command {
	case 0x01: // CONNECT
		var target string
		if atyp == 0x04 {
			target = fmt.Sprintf("[%s]:%d", host, port)
		} else {
			target = fmt.Sprintf("%s:%d", host, port)
		}

		log.Printf("[SOCKS5 / %s] %s -> %s", cfg.ListenAddr, clientAddr, target)

		if err := cfg.handleTunnel(conn, target, clientAddr, modeSOCKS5, nil); err != nil {
			if !isNormalCloseError(err) {
				log.Printf("[SOCKS5 / %s] %s 代理失败: %v", cfg.ListenAddr, clientAddr, err)
			}
		}

	case 0x03: // UDP ASSOCIATE
		cfg.handleUDPAssociate(conn, clientAddr)

	default:
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
}

// handleUDPAssociate, handleUDPRelay, handleDNSQuery 保持为 InstanceConfig 的方法
func (cfg *InstanceConfig) handleUDPAssociate(tcpConn net.Conn, clientAddr string) {
	if tcpConn == nil {
		return
	}

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		log.Printf("[UDP / %s] %s 解析地址失败: %v", cfg.ListenAddr, clientAddr, err)
		tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Printf("[UDP / %s] %s 监听失败: %v", cfg.ListenAddr, clientAddr, err)
		tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	port := localAddr.Port

	log.Printf("[UDP / %s] %s UDP ASSOCIATE 监听端口: %d", cfg.ListenAddr, clientAddr, port)

	response := []byte{0x05, 0x00, 0x00, 0x01}
	response = append(response, 127, 0, 0, 1) // 127.0.0.1
	response = append(response, byte(port>>8), byte(port&0xff))

	if _, err := tcpConn.Write(response); err != nil {
		udpConn.Close()
		return
	}

	stopChan := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go cfg.handleUDPRelay(udpConn, clientAddr, stopChan, &wg) 

	buf := make([]byte, 1)
	tcpConn.Read(buf)

	close(stopChan)
	wg.Wait() 
	udpConn.Close()
	log.Printf("[UDP / %s] %s UDP ASSOCIATE 连接关闭", cfg.ListenAddr, clientAddr)
}

func (cfg *InstanceConfig) handleUDPRelay(udpConn *net.UDPConn, clientAddr string, stopChan chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 65535)
	for {
		select {
		case <-stopChan:
			return
		default:
		}

		udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		data := buf[:n]

		if data[2] != 0x00 { // FRAG 必须为 0
			continue
		}

		atyp := data[3]
		var headerLen int
		var dstHost string
		var dstPort int

		switch atyp {
		case 0x01: // IPv4
			if n < 10 {
				continue
			}
			dstHost = net.IP(data[4:8]).String()
			dstPort = int(data[8])<<8 | int(data[9])
			headerLen = 10

		case 0x03: // 域名
			if n < 5 {
				continue
			}
			domainLen := int(data[4])
			if n < 7+domainLen {
				continue
			}
			dstHost = string(data[5 : 5+domainLen])
			dstPort = int(data[5+domainLen])<<8 | int(data[6+domainLen])
			headerLen = 7 + domainLen

		case 0x04: // IPv6
			if n < 22 {
				continue
			}
			dstHost = net.IP(data[4:20]).String()
			dstPort = int(data[20])<<8 | int(data[21])
			headerLen = 22

		default:
			continue
		}

		udpData := data[headerLen:]
		target := fmt.Sprintf("%s:%d", dstHost, dstPort)

		if dstPort == 53 {
			log.Printf("[UDP-DNS / %s] %s -> %s (DoH 查询)", cfg.ListenAddr, clientAddr, target)
			go cfg.handleDNSQuery(udpConn, addr, udpData, data[:headerLen]) 
		} else {
			log.Printf("[UDP / %s] %s -> %s (暂不支持非 DNS UDP)", cfg.ListenAddr, clientAddr, target)
		}
	}
}

func (cfg *InstanceConfig) handleDNSQuery(udpConn *net.UDPConn, clientAddr *net.UDPAddr, dnsQuery []byte, socks5Header []byte) {
	dnsResponse, err := cfg.queryDoHForProxy(dnsQuery) 
	if err != nil {
		log.Printf("[UDP-DNS / %s] DoH 查询失败: %v", cfg.ListenAddr, err)
		return
	}

	response := make([]byte, 0, len(socks5Header)+len(dnsResponse))
	response = append(response, socks5Header...)
	response = append(response, dnsResponse...)

	_, err = udpConn.WriteToUDP(response, clientAddr)
	if err != nil {
		log.Printf("[UDP-DNS / %s] 发送响应失败: %v", cfg.ListenAddr, err)
		return
	}

	log.Printf("[UDP-DNS / %s] DoH 查询成功，响应 %d 字节", cfg.ListenAddr, len(dnsResponse))
}

// ======================== HTTP 处理 (InstanceConfig 方法) ========================

// handleHTTP 现在是 InstanceConfig 的方法
func (cfg *InstanceConfig) handleHTTP(conn net.Conn, clientAddr string, firstByte byte) {
	if conn == nil {
		return
	}

	reader := bufio.NewReader(io.MultiReader(
		strings.NewReader(string(firstByte)),
		conn,
	))

	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	parts := strings.Fields(requestLine)
	if len(parts) < 3 {
		return
	}

	method := parts[0]
	requestURL := parts[1]
	httpVersion := parts[2]

	// 读取所有 headers
	headers := make(map[string]string)
	var headerLines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		headerLines = append(headerLines, line)
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			headers[strings.ToLower(key)] = value
		}
	}

	switch method {
	case "CONNECT":
		log.Printf("[HTTP-CONNECT / %s] %s -> %s", cfg.ListenAddr, clientAddr, requestURL)
		if err := cfg.handleTunnel(conn, requestURL, clientAddr, modeHTTPConnect, nil); err != nil {
			if !isNormalCloseError(err) {
				log.Printf("[HTTP-CONNECT / %s] %s 代理失败: %v", cfg.ListenAddr, clientAddr, err)
			}
		}

	case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE":
		log.Printf("[HTTP-%s / %s] %s -> %s", method, cfg.ListenAddr, clientAddr, requestURL)

		var target string
		var path string

		if strings.HasPrefix(requestURL, "http://") {
			urlWithoutScheme := strings.TrimPrefix(requestURL, "http://")
			idx := strings.Index(urlWithoutScheme, "/")
			if idx > 0 {
				target = urlWithoutScheme[:idx]
				path = urlWithoutScheme[idx:]
			} else {
				target = urlWithoutScheme
				path = "/"
			}
		} else {
			target = headers["host"]
			path = requestURL
		}

		if target == "" {
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}

		if !strings.Contains(target, ":") {
			target += ":80"
		}

		var requestBuilder strings.Builder
		requestBuilder.WriteString(fmt.Sprintf("%s %s %s\r\n", method, path, httpVersion))

		for _, line := range headerLines {
			key := strings.Split(line, ":")[0]
			keyLower := strings.ToLower(strings.TrimSpace(key))
			if keyLower != "proxy-connection" && keyLower != "proxy-authorization" {
				requestBuilder.WriteString(line)
				requestBuilder.WriteString("\r\n")
			}
		}
		requestBuilder.WriteString("\r\n")

		if contentLength := headers["content-length"]; contentLength != "" {
			var length int
			fmt.Sscanf(contentLength, "%d", &length)
			if length > 0 && length < 10*1024*1024 { // 限制 10MB
				body := make([]byte, length)
				if _, err := io.ReadFull(reader, body); err == nil {
					requestBuilder.Write(body)
				}
			}
		}

		firstFrame := requestBuilder.String()

		if err := cfg.handleTunnel(conn, target, clientAddr, modeHTTPProxy, []byte(firstFrame)); err != nil {
			if !isNormalCloseError(err) {
				log.Printf("[HTTP-%s / %s] %s 代理失败: %v", method, cfg.ListenAddr, clientAddr, err)
			}
		}

	default:
		log.Printf("[HTTP / %s] %s 不支持的方法: %s", cfg.ListenAddr, clientAddr, method)
		conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
	}
}

// ======================== 通用隧道处理 (InstanceConfig 方法) ========================

// 代理模式常量
const (
	modeSOCKS5      = 1 // SOCKS5 代理
	modeHTTPConnect = 2 // HTTP CONNECT 隧道
	modeHTTPProxy   = 3 // HTTP 普通代理（GET/POST等）
)

// handleTunnel 现在是 InstanceConfig 的方法
func (cfg *InstanceConfig) handleTunnel(conn net.Conn, target, clientAddr string, mode int, firstFrame []byte) error {
	if conn == nil {
		return errors.New("连接对象为空")
	}
	wsConn, err := cfg.dialWebSocketWithECH(2) // 调用 cfg.dialWebSocketWithECH
	if err != nil {
		sendErrorResponse(conn, mode)
		return err
	}
	defer func() {
		if wsConn != nil {
			wsConn.Close()
		}
	}()

	var mu sync.Mutex

	// 保活
	stopPing := make(chan bool)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				mu.Lock()
				wsConn.WriteMessage(websocket.PingMessage, nil)
				mu.Unlock()
			case <-stopPing:
				return
			}
		}
	}()
	defer close(stopPing)

	conn.SetDeadline(time.Time{})

	// 读取第一帧数据（SOCKS5/无请求体 HTTP）
	if firstFrame == nil && mode == modeSOCKS5 {
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		buffer := make([]byte, 32*1024) 
		n, _ := conn.Read(buffer)
		_ = conn.SetReadDeadline(time.Time{})
		if n > 0 {
			firstFrame = buffer[:n]
		}
	}

	// 构建连接消息，包含代理 IP 信息
	var connectMsg []byte
	if cfg.ProxyIP != "" {
		connectMsg = append([]byte(fmt.Sprintf("CONNECT:%s|", target)), firstFrame...)
		connectMsg = append(connectMsg, []byte(fmt.Sprintf("|%s", cfg.ProxyIP))...) // 使用 cfg.ProxyIP
	} else {
		connectMsg = append([]byte(fmt.Sprintf("CONNECT:%s|", target)), firstFrame...)
	}

	mu.Lock()
	err = wsConn.WriteMessage(websocket.TextMessage, connectMsg)
	mu.Unlock()
	if err != nil {
		sendErrorResponse(conn, mode)
		return err
	}

	// 等待响应
	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		sendErrorResponse(conn, mode)
		return err
	}

	response := string(msg)
	if strings.HasPrefix(response, "ERROR:") {
		sendErrorResponse(conn, mode)
		return errors.New(response)
	}
	if response != "CONNECTED" {
		sendErrorResponse(conn, mode)
		return fmt.Errorf("意外响应: %s", response)
	}

	// 发送成功响应（根据模式不同而不同）
	if err := sendSuccessResponse(conn, mode); err != nil {
		return err
	}

	log.Printf("🔗 [代理 / %s] %s 已连接: %s", cfg.ListenAddr, clientAddr, target)

	// 双向转发
	done := make(chan struct{})
	var once sync.Once
	closeDone := func() {
		once.Do(func() { close(done) })
	}

	// Client -> Server
	go func() {
		buf := make([]byte, 32768)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				mu.Lock()
				wsConn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
				mu.Unlock()
				closeDone()
				return
			}

			mu.Lock()
			err = wsConn.WriteMessage(websocket.BinaryMessage, buf[:n])
			mu.Unlock()
			if err != nil {
				closeDone()
				return
			}
		}
	}()

	// Server -> Client
	go func() {
		for {
			mt, msg, err := wsConn.ReadMessage()
			if err != nil {
				closeDone()
				return
			}

			if mt == websocket.TextMessage {
				if string(msg) == "CLOSE" {
					closeDone()
					return
				}
			}

			if _, err := conn.Write(msg); err != nil {
				closeDone()
				return
			}
		}
	}()

	<-done
	log.Printf("🛑 [代理 / %s] %s 已断开: %s", cfg.ListenAddr, clientAddr, target)
	return nil
}

// ======================== 响应辅助函数 (保持不变) ========================

func sendErrorResponse(conn net.Conn, mode int) {
	switch mode {
	case modeSOCKS5:
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	case modeHTTPConnect, modeHTTPProxy:
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
	}
}

func sendSuccessResponse(conn net.Conn, mode int) error {
	switch mode {
	case modeSOCKS5:
		_, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return err
	case modeHTTPConnect:
		_, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		return err
	case modeHTTPProxy:
		return nil
	}
	return nil
}
