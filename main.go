package main

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	// Read VCAP_APP_HOST and PORT environment variables set by Cloud Foundry.
	host := os.Getenv("VCAP_APP_HOST")
	if len(host) == 0 {
		host = "0.0.0.0"
	}

	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = "8080"
	}

	address := host + ":" + port

	// Register proxy on the default ServeMux.
	http.Handle("/", NewProxy())

	log.Printf("Starting ip-whitelist demo app, listening on [%s] ...\n", address)

	// Use an explicit HTTP server to protect against slow clients
	// and excessive idle connections.
	server := &http.Server{
		Addr:              address,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		Handler:           http.DefaultServeMux,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

type Proxy struct {
	SkipSSLValidation bool
	AllowedIPs        []net.IP
	AllowedSubnets    []*net.IPNet
	TrustedProxies    []*net.IPNet
	Transport         *http.Transport
}

func NewProxy() *Proxy {
	skipSSLEnvValue := os.Getenv("SKIP_SSL_VALIDATION")
	if len(skipSSLEnvValue) == 0 {
		skipSSLEnvValue = "false"
	}

	skipSSL, _ := strconv.ParseBool(skipSSLEnvValue)

	// --- PARSE ALLOWED_IPS AND CONFIG_IPS ONCE ON STARTUP ---
	// ALLOWED_IPS represents the base platform allowlist.
	// CONFIG_IPS represents the customer-managed allowlist.
	allowedIPsString := os.Getenv("ALLOWED_IPS")
	configIPsString := os.Getenv("CONFIG_IPS")

	var combinedIPs []string
	if len(strings.TrimSpace(allowedIPsString)) > 0 {
		combinedIPs = append(combinedIPs, allowedIPsString)
	}
	if len(strings.TrimSpace(configIPsString)) > 0 {
		combinedIPs = append(combinedIPs, configIPsString)
	}

	if len(combinedIPs) == 0 {
		log.Fatal("FATAL: Both ALLOWED_IPS and CONFIG_IPS are missing or empty. App cannot start securely.")
	}

	// Merge both lists into a single comma-separated string, then split
	fullAllowedString := strings.Join(combinedIPs, ",")
	rawAllowed := strings.Split(fullAllowedString, ",")

	var allowedIPs []net.IP
	var allowedSubnets []*net.IPNet

	for _, entry := range rawAllowed {
		entry = strings.TrimSpace(entry)

		if entry == "" {
			continue
		}

		if strings.Contains(entry, "/") {
			_, subnet, err := net.ParseCIDR(entry)

			if err != nil {
				log.Fatalf(
					"FATAL: Malformed data in ALLOWED_IPS or CONFIG_IPS. '%s' is not a valid CIDR block.",
					entry,
				)
			}

			allowedSubnets = append(allowedSubnets, subnet)
		} else {
			ip := net.ParseIP(entry)

			if ip == nil {
				log.Fatalf(
					"FATAL: Malformed data in ALLOWED_IPS or CONFIG_IPS. '%s' is not a valid IP address or CIDR block.",
					entry,
				)
			}

			allowedIPs = append(allowedIPs, ip)
		}
	}

	if len(allowedIPs) == 0 && len(allowedSubnets) == 0 {
		log.Fatal("FATAL: ALLOWED_IPS and CONFIG_IPS contain no valid IPs or subnets. App cannot start securely.")
	}

	// --- PARSE TRUSTED_IPS ONCE ON STARTUP ---
	trustedIPsString := os.Getenv("TRUSTED_IPS")

	if len(strings.TrimSpace(trustedIPsString)) == 0 {
		log.Fatal("FATAL: TRUSTED_IPS environment variable is missing or empty. App cannot start securely.")
	}

	var trustedProxies []*net.IPNet
	trustedList := strings.Split(trustedIPsString, ",")

	for _, cidr := range trustedList {
		cidr = strings.TrimSpace(cidr)

		if cidr == "" {
			continue
		}

		// First try to parse the value as a CIDR.
		_, ipNet, err := net.ParseCIDR(cidr)

		if err != nil {
			// If it is not a CIDR, allow a single IP and convert it
			// to /32 for IPv4 or /128 for IPv6.
			ip := net.ParseIP(cidr)

			if ip == nil {
				log.Fatalf(
					"FATAL: Malformed data in TRUSTED_IPS. '%s' is not a valid IP or CIDR block.",
					cidr,
				)
			}

			if ip.To4() != nil {
				_, ipNet, err = net.ParseCIDR(cidr + "/32")
			} else {
				_, ipNet, err = net.ParseCIDR(cidr + "/128")
			}

			if err != nil {
				log.Fatalf(
					"FATAL: Unable to parse TRUSTED_IPS entry '%s'.",
					cidr,
				)
			}
		}

		trustedProxies = append(trustedProxies, ipNet)
	}

	if len(trustedProxies) == 0 {
		log.Fatal("FATAL: TRUSTED_IPS environment variable contained no valid IPs or subnets.")
	}

	// Create the shared transport connection pool exactly once.
	sharedTransport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: skipSSL},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	return &Proxy{
		SkipSSLValidation: skipSSL,
		AllowedIPs:        allowedIPs,
		AllowedSubnets:    allowedSubnets,
		TrustedProxies:    trustedProxies,
		Transport:         sharedTransport,
	}
}

// isTrustedProxy checks whether an IP belongs to the trusted infrastructure
// defined in the TRUSTED_IPS Cloud Foundry environment variable.
func (p *Proxy) isTrustedProxy(ipStr string) bool {
	ip := net.ParseIP(ipStr)

	if ip == nil {
		return false
	}

	for _, network := range p.TrustedProxies {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

func (p *Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	p.ReverseProxy(rw, req)
}

func (p *Proxy) ReverseProxy(rw http.ResponseWriter, req *http.Request) {
	log.Printf(
		"proxying request: [%s; %s; %s]\n",
		req.Method,
		req.RequestURI,
		req.UserAgent(),
	)

	req.Header.Set("X-IP-Whitelisting-Proxy", "X-IP-Whitelisting-Proxy")

	// X-CF-Forwarded-Url is required to determine the target of the request
	// after it has been passed through the Cloud Foundry Route Service.
	targetURL := req.Header.Get("X-CF-Forwarded-Url")

	if len(targetURL) == 0 {
		rw.WriteHeader(http.StatusBadRequest)
		_, _ = rw.Write([]byte("Bad Request: Missing X-CF-Forwarded-Url header"))
		return
	}

	target, err := url.Parse(targetURL)
	if err != nil {
		log.Println(err.Error())
		rw.WriteHeader(http.StatusBadRequest)
		_, _ = rw.Write([]byte("Bad Request: " + err.Error()))
		return
	}

	// --- ROUTE SERVICE SECURITY VALIDATION ---
	// Cloud Foundry adds X-CF-Proxy-Signature when forwarding a request
	// to a route service. We cannot independently validate the signature here;
	// the presence check provides an additional defense against direct access
	// to the ACL application as an open proxy.
	if req.Header.Get("X-CF-Proxy-Signature") == "" {
		log.Printf("blocking direct request: missing X-CF-Proxy-Signature")
		rw.WriteHeader(http.StatusForbidden)
		_, _ = rw.Write([]byte("Forbidden: Direct access not allowed"))
		return
	}

	// --- RIGHT-TO-LEFT X-Forwarded-For PARSING ---
	xffHeader := req.Header.Get("X-Forwarded-For")
	ips := strings.Split(xffHeader, ",")

	var trueClientIP string
	var lastSeenIP string

	// Parse from right to left (end of array to beginning).
	for i := len(ips) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(ips[i])

		if ip == "" {
			continue
		}

		// Remember the last infrastructure IP seen.
		// This is used as a fallback for internal app-to-app traffic.
		lastSeenIP = ip

		// Skip trusted CF/STACKIT/F5 infrastructure.
		if p.isTrustedProxy(ip) {
			continue
		}

		// The first IP encountered that is not trusted infrastructure
		// is considered the client IP.
		trueClientIP = ip
		break
	}

	// If the complete XFF chain contained only trusted infrastructure,
	// treat the last seen infrastructure IP as the client IP.
	if trueClientIP == "" && lastSeenIP != "" {
		trueClientIP = lastSeenIP
	}

	// Fallback to RemoteAddr if XFF was completely empty or invalid.
	if trueClientIP == "" {
		host, _, err := net.SplitHostPort(req.RemoteAddr)

		if err == nil {
			trueClientIP = host
		} else {
			trueClientIP = req.RemoteAddr
		}
	}

	// Debug log to make the Right-to-Left parsing result visible.
	log.Printf(
		"DEBUG: XFF Chain: [%s] | True Client IP Identified: [%s]",
		xffHeader,
		trueClientIP,
	)

	// ---------------------------------------
	// ALLOWED_IPS & CONFIG_IPS authorization
	// ---------------------------------------
	var found bool
	clientIP := net.ParseIP(trueClientIP)

	if clientIP != nil {
		// 1. Direct IP match check from memory.
		for _, allowedIP := range p.AllowedIPs {
			if clientIP.Equal(allowedIP) {
				found = true
				break
			}
		}

		// 2. Subnet match check from memory.
		if !found {
			for _, subnet := range p.AllowedSubnets {
				if subnet.Contains(clientIP) {
					found = true
					break
				}
			}
		}
	}

	if !found {
		log.Printf(
			"blocking request from Identified Client IP [%s]",
			trueClientIP,
		)

		rw.WriteHeader(http.StatusForbidden)
		_, _ = rw.Write([]byte("Forbidden"))
		return
	}

	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	req.Host = target.Host
	req.URL.Path = target.Path

	target.Path = ""

	// Setup the reverse proxy and forward the original request to the target.
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Reuse the shared HTTP connection pool.
	proxy.Transport = p.Transport

	proxy.ServeHTTP(rw, req)
}