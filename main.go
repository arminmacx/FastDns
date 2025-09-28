// ** PART 1: Imports **
package main

import (
	"context" // Added for semaphore in DB refresher
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net" // Added for IP formatting in handleRequest logging
	"os"
	"os/signal"
	"strconv" // Needed for port formatting
	"strings" // Used in handleRequest, cacheKey, parseCacheKey
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/miekg/dns"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sync/semaphore" // Added for semaphore in DB refresher
	"gopkg.in/yaml.v2"
)

// ** END PART 1 **
// ** PART 2: Constants and Structs **

// Default value for the refresh interval if not specified in YAML
const defaultDBRefreshIntervalString = "1m"

// Config holds all configuration settings for the DNS proxy server.
// (Based on your provided config structure)
type Config struct {
	ListenIP    string     `yaml:"listen_ip"`
	ListenPort  int        `yaml:"listen_port"`
	DBPath      string     `yaml:"db_path"`
	CacheTTL    uint32     `yaml:"cache_ttl_seconds"`    // Default TTL for positive cache entries
	NegativeTTL uint32     `yaml:"negative_ttl_seconds"` // TTL for NXDOMAIN or error responses
	DNSSEC      bool       `yaml:"dnssec_enabled"`       // Whether to request DNSSEC records (DO bit)
	Upstreams   []Upstream `yaml:"upstreams"`
	// Blocklists []Blocklist `yaml:"blocklists"` // Include if you have blocklists

	DBRefreshIntervalString string        `yaml:"db_refresh_interval"` // User-facing string
	DBRefreshInterval       time.Duration `yaml:"-"`                   // Parsed duration (Internal)
}

// Upstream defines a single upstream DNS server.
// (Based on your provided Upstream struct)
type Upstream struct {
	Name    string `yaml:"name"`    // Optional name for logging/identification
	Address string `yaml:"address"` // IP:Port format, e.g., "1.1.1.1:53"
	Type    string `yaml:"type"`    // e.g., "udp", "tcp", "dot", "doh" (Used by UpstreamPool logic)
}

// Blocklist struct (if used)
// type Blocklist struct { ... }

// Constants for other defaults
// (Based on your provided defaults)
const (
	defaultListenIP    = "127.0.0.1"
	defaultListenPort  = 53
	defaultDBPath      = "./fasdns_cache.db"
	defaultCacheTTL    = 3600 // 1 hour
	defaultNegativeTTL = 300  // 5 minutes
	defaultDNSSEC      = false
	cacheBucketName    = "cache" // Consistent with your code
)

// Server holds the state of the DNS proxy server.
// (Based on your provided Server struct)
type Server struct {
	cfg          *Config       // Reference to the loaded configuration
	db           *bolt.DB      // BoltDB database connection
	udpServer    *dns.Server   // UDP listener
	tcpServer    *dns.Server   // TCP listener
	stats        *Stats        // Request/cache hit statistics
	upstreamPool *UpstreamPool // Pool for managing upstream connections/queries
	shutdownChan chan struct{} // Channel to signal shutdown
	// Add other fields like blocklist manager if needed
}

// Stats holds counters for server operations.
// (Based on your provided Stats struct)
type Stats struct {
	TotalQueries   uint64
	CacheHits      uint64
	CacheMisses    uint64
	UpstreamErrors uint64
	BlockedQueries uint64 // If using blocklists
	sync.RWMutex          // To protect concurrent access to stats
}

// CacheEntry defines the structure stored in the cache database.
// (Based on your provided CacheEntry struct for runFullDBRefresh)
type CacheEntry struct {
	Msg        []byte    `json:"msg"` // Packed/Serialized dns.Msg
	ExpiryTime time.Time `json:"expiryTime"`
}

// UpstreamPool manages upstream servers and querying logic.
// Needs implementation details based on your requirements (round-robin, health checks etc.)
type UpstreamPool struct {
	upstreams []Upstream // List of configured upstreams
	// Add state like current index for round-robin, mutexes, health status etc.
	client     *dns.Client // DNS client shared by the pool
	sync.Mutex             // For managing concurrent access if needed (e.g., round-robin index)
}

// ** END PART 2 **
// ** PART 3: Configuration Loading **

// loadConfig reads the YAML configuration file, sets defaults, validates, and parses durations.
// (Based on your provided loadConfig function)
func loadConfig(path string) (*Config, error) {
	// Set defaults *before* reading the file
	cfg := &Config{
		ListenIP:                defaultListenIP,
		ListenPort:              defaultListenPort,
		DBPath:                  defaultDBPath,
		CacheTTL:                defaultCacheTTL,
		NegativeTTL:             defaultNegativeTTL,
		DNSSEC:                  defaultDNSSEC,
		Upstreams:               make([]Upstream, 0),
		DBRefreshIntervalString: defaultDBRefreshIntervalString, // Default interval string
	}

	data, err := os.ReadFile(path)
	if err != nil {
		// Only return error if a specific file was *expected* but not found/readable
		// If allowing operation with defaults, log a warning instead.
		// Example: Return error if config file specified via flag is mandatory.
		if !os.IsNotExist(err) { // Handle read errors other than file not found
			return nil, fmt.Errorf("failed to read config file '%s': %w", path, err)
		}
		log.Printf("WARN: Config file '%s' not found, using default settings.", path)
		// Proceed with defaults if file not found is acceptable
	} else {
		// Unmarshal YAML into the struct only if file was read
		err = yaml.Unmarshal(data, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to parse config file '%s': %w", path, err)
		}
		log.Printf("Config loaded successfully from %s", path)
	}

	// --- Validation and Parsing ---
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		return nil, fmt.Errorf("invalid listen_port '%d': must be between 1 and 65535", cfg.ListenPort)
	}

	if len(cfg.Upstreams) == 0 {
		log.Println("WARN: No upstreams defined in configuration, upstream queries will fail.")
		// Depending on requirements, this might be an error:
		// return nil, fmt.Errorf("configuration must include at least one upstream DNS server")
	} else {
		// Validate upstream addresses format maybe?
		for i, up := range cfg.Upstreams {
			if _, _, err := net.SplitHostPort(up.Address); err != nil {
				return nil, fmt.Errorf("invalid address format for upstream '%s' (%s): %w. Expected host:port", up.Name, up.Address, err)
			}
			// Validate Type? (e.g., ensure it's udp, tcp, dot, doh)
			upType := strings.ToLower(up.Type)
			if upType != "udp" && upType != "tcp" && upType != "dot" && upType != "doh" {
				log.Printf("WARN: Upstream %d ('%s') has potentially unsupported type '%s'. Assuming 'udp'.", i, up.Name, up.Type)
				// Optionally default it: cfg.Upstreams[i].Type = "udp"
			}
		}
	}

	// --- Parse and Validate DBRefreshInterval ---
	parsedInterval, err := time.ParseDuration(cfg.DBRefreshIntervalString)
	if err != nil {
		return nil, fmt.Errorf("invalid format for db_refresh_interval '%s': %w. Use format like '30s', '5m', '1h'", cfg.DBRefreshIntervalString, err)
	}
	if parsedInterval <= 0 { // Ensure positive interval
		// Maybe allow 0 to disable refresh? Check requirements.
		// return nil, fmt.Errorf("db_refresh_interval '%s' must be positive", cfg.DBRefreshIntervalString)
		log.Printf("WARN: db_refresh_interval '%s' is not positive. DB Refresh will be disabled.", cfg.DBRefreshIntervalString)
		cfg.DBRefreshInterval = 0 // Explicitly set to zero duration
	} else {
		cfg.DBRefreshInterval = parsedInterval // Store the parsed time.Duration
		log.Printf("DB Refresh interval set to: %v", cfg.DBRefreshInterval)
	}
	// --- End Parse/Validate DBRefreshInterval ---

	// Add validation for other fields as needed (DBPath writeable?, etc.)

	return cfg, nil
}

// ** END PART 3 **
// ** PART 4: Server Initialization **

// NewUpstreamPool creates a new UpstreamPool.
func NewUpstreamPool(upstreams []Upstream) *UpstreamPool {
	return &UpstreamPool{
		upstreams: upstreams,
		client:    &dns.Client{Timeout: 5 * time.Second}, // Example: Set a client timeout
		// Initialize other pool state if needed
	}
}

// NewServer creates and initializes a new Server instance.
// (Based on your provided NewServer function)
func NewServer(cfg *Config) (*Server, error) {
	// --- Open BoltDB ---
	db, err := bolt.Open(cfg.DBPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open database '%s': %w", cfg.DBPath, err)
	}
	log.Printf("Database opened successfully: %s", cfg.DBPath)

	// Ensure the cache bucket exists
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(cacheBucketName))
		if err != nil {
			return fmt.Errorf("failed to create cache bucket '%s': %w", cacheBucketName, err)
		}
		return nil
	})
	if err != nil {
		db.Close() // Close DB if bucket creation failed
		return nil, fmt.Errorf("failed ensuring cache bucket: %w", err)
	}
	log.Printf("Cache bucket '%s' ensured in database.", cacheBucketName)

	srv := &Server{
		cfg:          cfg,
		db:           db,
		stats:        &Stats{},                       // Initialize stats
		upstreamPool: NewUpstreamPool(cfg.Upstreams), // Initialize upstream pool
		shutdownChan: make(chan struct{}),            // Initialize shutdown channel
	}

	// Setup DNS handlers (use srv.handleRequest as the handler)
	mux := dns.NewServeMux()
	mux.HandleFunc(".", srv.handleRequest) // Handle all queries

	// Create DNS Server listeners
	listenAddr := fmt.Sprintf("%s:%d", cfg.ListenIP, cfg.ListenPort)
	srv.udpServer = &dns.Server{Addr: listenAddr, Net: "udp", Handler: mux, ReusePort: true}
	srv.tcpServer = &dns.Server{Addr: listenAddr, Net: "tcp", Handler: mux, ReusePort: true}

	return srv, nil
}

// ** END PART 4 **
// ** PART 5: Core Request Handling (handleRequest) **

// handleRequest processes incoming DNS requests.
// THIS FUNCTION CONTAINS THE REQUESTED UPSTREAM LOGGING MODIFICATIONS.
func (s *Server) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	startTime := time.Now()
	s.stats.IncTotalQueries() // Use stat methods for thread safety

	if r == nil || len(r.Question) == 0 {
		log.Printf("WARN [Query: %d] Received empty or invalid request from %s", r.Id, w.RemoteAddr().String())
		dns.HandleFailed(w, r)
		return
	}

	q := r.Question[0]
	qName := strings.ToLower(q.Name) // Normalize name for consistency
	qTypeStr := dns.TypeToString[q.Qtype]
	clientIP := w.RemoteAddr().String()

	// Use color for visibility
	log.Printf(color.CyanString("[Query: %d]")+" Received %s %s from %s", r.Id, qName, qTypeStr, clientIP)

	// --- TODO: Implement Blocklist Check if needed ---
	// if s.isBlocked(qName) {
	//     s.stats.IncBlockedQueries()
	//     log.Printf("[Blocked: %d] Denied %s %s for %s", r.Id, qName, qTypeStr, clientIP)
	//     // Construct and send NXDOMAIN or appropriate block response
	//     m := new(dns.Msg)
	//     m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN common for blocking
	//     w.WriteMsg(m)
	//     return
	// }

	// --- Check Cache ---
	cacheKey := cacheKey(q) // Generate key using normalized name
	log.Printf("[Cache: %d] Checking cache for key: %s (%s %s)", r.Id, cacheKey, qName, qTypeStr)

	var cachedMsg *dns.Msg
	var cacheHit bool

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(cacheBucketName))
		if b == nil {
			log.Printf("ERROR [Cache: %d] Cache bucket '%s' not found during lookup for %s", r.Id, cacheBucketName, cacheKey)
			return fmt.Errorf("cache bucket '%s' not found", cacheBucketName) // Should not happen
		}
		cachedData := b.Get([]byte(cacheKey))
		if cachedData == nil {
			log.Printf("[Cache: %d] Miss for %s %s", r.Id, qName, qTypeStr)
			return nil // Cache miss
		}

		var entry CacheEntry
		if err := json.Unmarshal(cachedData, &entry); err != nil {
			log.Printf("WARN [Cache: %d] Failed to unmarshal cache data for key %s: %v. Treating as miss.", r.Id, cacheKey, err)
			// Optionally delete corrupted entry in a separate Update tx
			return nil
		}

		if time.Now().After(entry.ExpiryTime) {
			log.Printf("[Cache: %d] Expired entry found for %s %s (Expired: %s)", r.Id, qName, qTypeStr, entry.ExpiryTime.Format(time.RFC3339))
			// Optionally delete expired entry in a separate Update tx
			return nil // Treat as miss
		}

		// Entry is valid and not expired
		msg := new(dns.Msg)
		if err := msg.Unpack(entry.Msg); err != nil {
			log.Printf("WARN [Cache: %d] Failed to unpack cached DNS message for key %s: %v. Treating as miss.", r.Id, cacheKey, err)
			// Optionally delete corrupted entry
			return nil
		}

		// Adjust TTLs in the cached message based on remaining time
		// This prevents clients from caching for longer than the entry is valid here.
		remainingTTL := uint32(time.Until(entry.ExpiryTime).Seconds())
		if remainingTTL < 0 {
			remainingTTL = 0
		} // Ensure non-negative
		for _, rr := range msg.Answer {
			rr.Header().Ttl = remainingTTL
		}
		for _, rr := range msg.Ns {
			rr.Header().Ttl = remainingTTL
		}
		// We don't adjust Extra section usually

		log.Printf(color.GreenString("[Cache: %d]")+" Hit for %s %s (Expires: %s, Remaining TTL: %ds)", r.Id, qName, qTypeStr, entry.ExpiryTime.Format(time.RFC3339), remainingTTL)
		cachedMsg = msg
		cacheHit = true
		s.stats.IncCacheHits() // Use stat methods
		return nil
	})

	if err != nil {
		// Log error during DB access, but still attempt upstream query
		log.Printf("ERROR [Cache: %d] Failed to access cache DB for key %s: %v", r.Id, cacheKey, err)
		// Continue to upstream query
	}

	// If Cache Hit, respond and exit
	if cacheHit && cachedMsg != nil {
		response := new(dns.Msg)
		response.SetReply(r)
		// Copy sections from the (potentially TTL-adjusted) cached message
		response.Answer = cachedMsg.Answer
		response.Ns = cachedMsg.Ns
		response.Extra = cachedMsg.Extra
		response.Rcode = cachedMsg.Rcode

		if err := w.WriteMsg(response); err != nil {
			log.Printf("ERROR [Response: %d] Failed to write CACHED response to %s for %s %s: %v", r.Id, clientIP, qName, qTypeStr, err)
		} else {
			duration := time.Since(startTime)
			log.Printf(color.HiGreenString("[Response: %d]")+" Sent CACHED reply for %s %s to %s (took %v)", r.Id, qName, qTypeStr, clientIP, duration)
		}
		return // <<< EXIT HERE ON CACHE HIT
	}

	// --- Cache Miss or Error ---
	s.stats.IncCacheMisses() // Use stat methods

	// ******************************************************************
	// ******** MODIFIED LOGGING: Before sending upstream query ********
	// ******************************************************************
	log.Printf(color.YellowString("[Upstream: %d]")+" Attempting upstream query for ---> %s %s <---", r.Id, qName, qTypeStr)

	// --- Query Upstream ---
	upstreamMsg, upstreamAddrUsed, err := s.upstreamPool.Query(r) // Pass the original request for EDNS options etc.

	if err != nil {
		log.Printf(color.RedString("ERROR [Upstream: %d]")+" Upstream query failed for %s %s (using %s): %v", r.Id, qName, qTypeStr, upstreamAddrUsed, err)
		s.stats.IncUpstreamErrors() // Use stat methods
		dns.HandleFailed(w, r)      // Send SERVFAIL back to client
		return
	}

	// ******************************************************************
	// ******** NEW LOGGING: After receiving upstream response ********
	// ******************************************************************
	var answerSummary []string
	if upstreamMsg != nil && len(upstreamMsg.Answer) > 0 {
		for _, ans := range upstreamMsg.Answer {
			// Simple summary: Type: Data
			answerSummary = append(answerSummary, fmt.Sprintf("%s: %s", dns.TypeToString[ans.Header().Rrtype], rrDataToString(ans)))
		}
	} else if upstreamMsg != nil {
		answerSummary = append(answerSummary, "NoAnswer") // Indicate no records in Answer section
	} else {
		answerSummary = append(answerSummary, "NilResponse") // Should not happen if err == nil
	}

	log.Printf(color.HiYellowString("[Upstream: %d]")+" Received reply from %s for <--- %s %s <--- | RCODE: %s | Answers: %d [%s]",
		r.Id,
		upstreamAddrUsed, // Log which upstream was used
		qName,
		qTypeStr,
		dns.RcodeToString[upstreamMsg.Rcode],
		len(upstreamMsg.Answer),
		strings.Join(answerSummary, ", "),
	)
	// ******************************************************************
	// ******** END NEW LOGGING *****************************************
	// ******************************************************************

	// --- Cache the Upstream Response ---
	isNegative := upstreamMsg.Rcode == dns.RcodeNameError || upstreamMsg.Rcode == dns.RcodeServerFailure // Add other codes if needed
	ttl := s.getEffectiveTTL(upstreamMsg, isNegative)                                                    // Use YOUR getEffectiveTTL logic

	if ttl > 0 && upstreamMsg.Rcode != dns.RcodeServerFailure { // Only cache if TTL is positive and not SERVFAIL (usually)
		packedMsg, packErr := upstreamMsg.Pack()
		if packErr != nil {
			log.Printf("ERROR [Cache: %d] Failed to pack upstream DNS response for %s %s: %v", r.Id, qName, qTypeStr, packErr)
		} else {
			expiry := time.Now().Add(time.Duration(ttl) * time.Second)
			cacheEntry := CacheEntry{
				Msg:        packedMsg,
				ExpiryTime: expiry,
			}
			jsonData, jsonErr := json.Marshal(cacheEntry)
			if jsonErr != nil {
				log.Printf("ERROR [Cache: %d] Failed to marshal cache entry for %s %s: %v", r.Id, qName, qTypeStr, jsonErr)
			} else {
				dbErr := s.db.Update(func(tx *bolt.Tx) error {
					b := tx.Bucket([]byte(cacheBucketName))
					if b == nil {
						log.Printf("ERROR [Cache: %d] Cache bucket missing during save for key %s", r.Id, cacheKey)
						return fmt.Errorf("cache bucket missing during save")
					}
					log.Printf("[Cache: %d] Storing entry for %s (%s %s) with TTL %ds (Expires: %s)", r.Id, cacheKey, qName, qTypeStr, ttl, expiry.Format(time.RFC3339))
					return b.Put([]byte(cacheKey), jsonData) // Use generated cacheKey
				})
				if dbErr != nil {
					log.Printf("ERROR [Cache: %d] Failed to save cache entry for %s %s to DB: %v", r.Id, qName, qTypeStr, dbErr)
				}
			}
		}
	} else {
		log.Printf("[Cache: %d] Not caching response for %s %s (TTL: %d, RCODE: %s)", r.Id, qName, qTypeStr, ttl, dns.RcodeToString[upstreamMsg.Rcode])
	}

	// --- Send Upstream Response to Client ---
	// The upstreamMsg already has correct ID etc. from exchange
	// Important: Do NOT use SetReply here on upstreamMsg as it might overwrite things.
	// Just send the upstreamMsg directly.
	if err := w.WriteMsg(upstreamMsg); err != nil {
		log.Printf("ERROR [Response: %d] Failed to write UPSTREAM response to %s for %s %s: %v", r.Id, clientIP, qName, qTypeStr, err)
	} else {
		duration := time.Since(startTime)
		log.Printf(color.HiMagentaString("[Response: %d]")+" Sent UPSTREAM reply for %s %s to %s (took %v)", r.Id, qName, qTypeStr, clientIP, duration)
	}
}

// rrDataToString provides a concise string representation of RR data for logging.
func rrDataToString(rr dns.RR) string {
	switch r := rr.(type) {
	case *dns.A:
		return r.A.String()
	case *dns.AAAA:
		return r.AAAA.String()
	case *dns.CNAME:
		return r.Target
	case *dns.MX:
		return fmt.Sprintf("%d %s", r.Preference, r.Mx)
	case *dns.NS:
		return r.Ns
	case *dns.PTR:
		return r.Ptr
	case *dns.SOA:
		return fmt.Sprintf("%s %s %d", r.Ns, r.Mbox, r.Serial) // Example SOA summary
	case *dns.SRV:
		return fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, r.Target)
	case *dns.TXT:
		// Join strings, potentially truncate if very long
		txtData := strings.Join(r.Txt, "; ")
		if len(txtData) > 100 {
			return txtData[:97] + "..."
		}
		return "\"" + txtData + "\""
	default:
		// Fallback for other types
		return rr.String() // Use the default String() method, might be verbose
	}
}

// ** END PART 5 **
// ** PART 6: Upstream Pool Logic **

// Query selects an upstream server and sends the DNS query.
// Needs more sophisticated logic (round-robin, health checks).
// Takes the original request `r` to potentially use EDNS options.
// Returns the response, the address of the upstream used, and error.
func (p *UpstreamPool) Query(r *dns.Msg) (*dns.Msg, string, error) {
	if len(p.upstreams) == 0 {
		return nil, "None", fmt.Errorf("no upstreams configured")
	}

	// --- TODO: Implement proper upstream selection (round-robin, health checks) ---
	// Simplistic: Always use the first upstream defined.
	selectedUpstream := p.upstreams[0]
	upstreamAddr := selectedUpstream.Address
	// Use Type from config if needed (e.g., p.client.Net = selectedUpstream.Type)
	// For now, assume UDP default from dns.Client unless specified otherwise.
	// --- End TODO ---

	// Use the shared client
	// Pass the original request `r` to client.Exchange to preserve ID, EDNS options etc.
	reply, _, err := p.client.Exchange(r, upstreamAddr)
	if err != nil {
		// Log specific error from exchange
		log.Printf("DEBUG [UpstreamPool] Error querying %s for %s: %v", upstreamAddr, r.Question[0].Name, err)
		return nil, upstreamAddr, fmt.Errorf("query to %s failed: %w", upstreamAddr, err)
	}

	// Optional: Check reply RCODE here? Might depend on caller's needs.
	// if reply == nil { return nil, upstreamAddr, fmt.Errorf("received nil reply from %s", upstreamAddr) }

	return reply, upstreamAddr, nil
}

// ** END PART 6 **
// ** PART 7: Helper Functions **

// --- Cache Key Generation ---
// cacheKey generates a key for storing/retrieving cache entries.
// Uses Name:Type format from your example. Ensures name is lowercase.
func cacheKey(q dns.Question) string {
	return fmt.Sprintf("%s:%d", strings.ToLower(q.Name), q.Qtype)
}

// parseCacheKey reconstructs question details from a cache key.
// Needed by DB Refresher. Assumes "name:typeID" format.
func parseCacheKey(key string) (qname string, qtype uint16, err error) {
	parts := strings.SplitN(key, ":", 2)
	if len(parts) != 2 {
		err = fmt.Errorf("invalid key format: expected 'name:typeID', got '%s'", key)
		return
	}
	qname = parts[0] // Name is already lowercased if cacheKey uses ToLower

	typeInt, err := strconv.Atoi(parts[1])
	if err != nil {
		err = fmt.Errorf("invalid type ID in key '%s': %w", key, err)
		return
	}
	if typeInt < 0 || typeInt > 65535 {
		err = fmt.Errorf("type ID out of range in key '%s': %d", key, typeInt)
		return
	}
	qtype = uint16(typeInt)
	return qname, qtype, nil
}

// --- TTL Calculation ---
// getEffectiveTTL calculates the appropriate TTL for caching.
// ** REPLACE/VERIFY WITH YOUR ACTUAL LOGIC from getEffectiveTTL **
// This is a basic placeholder based on common practices.
func (s *Server) getEffectiveTTL(msg *dns.Msg, isNegative bool) uint32 {
	if msg == nil {
		return 0 // Cannot determine TTL from nil message
	}

	if isNegative {
		// Use NegativeTTL from config if set, otherwise don't cache negative
		if s.cfg.NegativeTTL > 0 {
			// Check SOA minimum TTL if present in Authority section for NXDOMAIN
			minTTLFromSOA := getSOAMinTTL(msg)
			if minTTLFromSOA > 0 && minTTLFromSOA < s.cfg.NegativeTTL {
				// Respect SOA minimum if lower than configured NegativeTTL
				// log.Printf("DEBUG [TTL] Using SOA Minimum TTL %d for negative cache of %s", minTTLFromSOA, msg.Question[0].Name)
				return minTTLFromSOA
			}
			// log.Printf("DEBUG [TTL] Using configured Negative TTL %d for %s", s.cfg.NegativeTTL, msg.Question[0].Name)
			return s.cfg.NegativeTTL
		}
		// log.Printf("DEBUG [TTL] Negative caching disabled or NegativeTTL is 0 for %s", msg.Question[0].Name)
		return 0 // Do not cache negative responses if NegativeTTL is 0
	}

	// --- Positive TTL Calculation ---
	// Should only cache successful responses (NOERROR)
	if msg.Rcode != dns.RcodeSuccess {
		// log.Printf("DEBUG [TTL] Not caching non-success RCODE %s for %s", dns.RcodeToString[msg.Rcode], msg.Question[0].Name)
		return 0
	}

	// Find the minimum TTL across all Answer and Authority section records
	// Start with a large value or the configured default TTL
	minTTL := s.cfg.CacheTTL // Use configured default/max as starting point
	foundRecordTTL := false

	rrSets := append(msg.Answer, msg.Ns...) // Combine Answer and Authority
	if len(rrSets) > 0 {
		// Use first record's TTL as initial minimum if lower than default
		firstTTL := rrSets[0].Header().Ttl
		if firstTTL < minTTL {
			minTTL = firstTTL
		}
		foundRecordTTL = true

		// Iterate over all records to find the absolute minimum
		for _, rr := range rrSets {
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
	}

	// What if no records in Answer/Authority but Rcode is NOERROR? (e.g., NODATA response)
	// Often, SOA is in Authority section. Use its minimum TTL if available.
	if !foundRecordTTL {
		soaMinTTL := getSOAMinTTL(msg)
		if soaMinTTL > 0 {
			// log.Printf("DEBUG [TTL] No Answer/NS records for %s, using SOA Minimum TTL: %d", msg.Question[0].Name, soaMinTTL)
			minTTL = soaMinTTL
			foundRecordTTL = true // We found *a* TTL value
		} else {
			// No records, no SOA min TTL -> cannot determine TTL, don't cache.
			// log.Printf("DEBUG [TTL] Cannot determine TTL for %s (NOERROR, no records, no SOA min TTL)", msg.Question[0].Name)
			return 0
		}
	}

	// Clamp TTL based on configured CacheTTL (acting as max)
	if s.cfg.CacheTTL > 0 && minTTL > s.cfg.CacheTTL {
		// log.Printf("DEBUG [TTL] Clamping TTL %d to max %d for %s", minTTL, s.cfg.CacheTTL, msg.Question[0].Name)
		minTTL = s.cfg.CacheTTL
	}

	// Optional: Enforce a minimum TTL (e.g., 10 seconds) if desired
	// const minimumCacheTTL uint32 = 10
	// if minTTL < minimumCacheTTL {
	//     log.Printf("DEBUG [TTL] Bumping TTL %d to minimum %d for %s", minTTL, minimumCacheTTL, msg.Question[0].Name)
	//     minTTL = minimumCacheTTL
	// }

	// ** PART 7: Helper Functions (Continued) **

	// log.Printf("DEBUG [TTL] Determined effective TTL %d for %s", minTTL, msg.Question[0].Name)
	return minTTL
}

// getSOAMinTTL extracts the minimum TTL field from the SOA record in the Authority section,
// which is often used as the negative caching TTL per RFC 2308.
func getSOAMinTTL(msg *dns.Msg) uint32 {
	if msg == nil {
		return 0
	}
	for _, rr := range msg.Ns { // Check Authority section for SOA
		if soa, ok := rr.(*dns.SOA); ok {
			// The last field in the SOA RDATA is the Minimum TTL.
			// log.Printf("DEBUG [TTL] Found SOA Minimum TTL %d for %s", soa.Minttl, soa.Hdr.Name)
			return soa.Minttl
		}
	}
	// log.Printf("DEBUG [TTL] No SOA record found in Authority section for %s", msg.Question[0].Name)
	return 0 // Return 0 if no SOA record found
}

// --- Stats Methods (Thread-Safe) ---

func (s *Stats) IncTotalQueries() {
	atomic.AddUint64(&s.TotalQueries, 1)
}

func (s *Stats) IncCacheHits() {
	s.Lock() // Use RWMutex for potential future reads/writes
	s.CacheHits++
	s.Unlock()
}

func (s *Stats) IncCacheMisses() {
	s.Lock()
	s.CacheMisses++
	s.Unlock()
}

func (s *Stats) IncUpstreamErrors() {
	s.Lock()
	s.UpstreamErrors++
	s.Unlock()
}

func (s *Stats) IncBlockedQueries() {
	s.Lock()
	s.BlockedQueries++
	s.Unlock()
}

// GetStats returns a copy of the current statistics.
func (s *Stats) GetStats() Stats {
	s.RLock() // Use read lock for concurrent reads
	defer s.RUnlock()
	// Return a copy to avoid race conditions on the returned struct
	return Stats{
		TotalQueries:   atomic.LoadUint64(&s.TotalQueries), // Use atomic load for consistency
		CacheHits:      s.CacheHits,
		CacheMisses:    s.CacheMisses,
		UpstreamErrors: s.UpstreamErrors,
		BlockedQueries: s.BlockedQueries,
	}
}

// ** END PART 7 **
// ** PART 8: Background Database Refresher **

// startDBRefresher launches a goroutine that periodically runs runFullDBRefresh.
// (Based on your provided main function logic and adding shutdown signal)
func (s *Server) startDBRefresher() {
	if s.cfg.DBRefreshInterval <= 0 {
		log.Println("DB Refresh interval is zero or negative, refresher disabled.")
		return
	}

	log.Printf("Starting background DB refresher with interval %v", s.cfg.DBRefreshInterval)
	go func() {
		// Create a ticker that fires based on the configured interval
		ticker := time.NewTicker(s.cfg.DBRefreshInterval)
		defer ticker.Stop() // Ensure ticker is stopped when goroutine exits

		// Run once immediately on startup (optional, but often useful)
		s.runFullDBRefresh()

		for {
			select {
			case <-ticker.C:
				// Time to refresh the database
				s.runFullDBRefresh()
			case <-s.shutdownChan:
				// Received shutdown signal, exit the goroutine
				log.Println("DB Refresher: Received shutdown signal, stopping...")
				return
			}
		}
	}()
}

// runFullDBRefresh iterates through cached entries, checks expiry,
// and potentially re-queries upstream to refresh/validate entries.
// (Based closely on your provided runFullDBRefresh logic from pasted-text.txt, page 5)
// Added semaphore for concurrency limiting.
func (s *Server) runFullDBRefresh() {
	log.Println(color.MagentaString("[DB REFRESH] Starting cache refresh cycle..."))
	startTime := time.Now()

	var processedCount uint64
	var updatedCount uint64
	var removedCount uint64
	var errorCount uint64

	// --- Concurrency Limiting ---
	// Limit concurrent upstream queries during refresh
	// Adjust the number based on system resources and upstream rate limits
	maxConcurrentRefreshes := 10
	sem := semaphore.NewWeighted(int64(maxConcurrentRefreshes))
	ctx := context.Background() // Context for semaphore acquisition
	var wg sync.WaitGroup

	errView := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(cacheBucketName))
		if b == nil {
			return fmt.Errorf("cache bucket '%s' not found", cacheBucketName)
		}

		c := b.Cursor()

		// Iterate over all keys in the cache bucket
		for k, v := c.First(); k != nil; k, v = c.Next() {
			atomic.AddUint64(&processedCount, 1)

			key := string(k) // Capture key for goroutine

			var entry CacheEntry
			var err error
			if err := json.Unmarshal(v, &entry); err != nil {
				log.Printf("WARN [DB REFRESH] Failed to unmarshal entry for key '%s': %v. Removing entry.", key, err)
				// Need an Update transaction to delete
				// We'll handle deletion within the goroutine's update tx
				atomic.AddUint64(&errorCount, 1)
				// Continue processing other keys, but mark this one for potential removal
			}

			// --- Check Expiry ---
			// Check if nearing expiry (e.g., within the next refresh interval or a fixed window)
			// This determines if we should *attempt* a refresh.
			// Example: Refresh if expires within the next 2 * refresh interval
			refreshThreshold := time.Now().Add(2 * s.cfg.DBRefreshInterval) // Adjust logic as needed
			if entry.ExpiryTime.After(refreshThreshold) && err == nil {
				// Entry is valid and not expiring soon, skip refresh attempt
				// log.Printf("DEBUG [DB REFRESH] Skipping refresh for %s, expires %s", key, entry.ExpiryTime.Format(time.RFC3339))
				continue
			}

			// --- Prepare for Refresh Goroutine ---
			qname, qtype, parseErr := parseCacheKey(key) // Use updated parseCacheKey
			if parseErr != nil {
				log.Printf("ERROR [DB REFRESH] Failed to parse cache key '%s': %v. Cannot refresh.", key, parseErr)
				atomic.AddUint64(&errorCount, 1)
				// Consider removing malformed key entry here or later
				continue
			}

			question := dns.Question{
				Name:   qname, // Already lowercased by cacheKey
				Qtype:  qtype,
				Qclass: dns.ClassINET, // Assume INET class
			}

			wg.Add(1)
			go func(q dns.Question, k string, currentData []byte) { // Pass key and current data
				defer wg.Done()

				// Acquire semaphore, respect context for cancellation (though not strictly needed here)
				if err := sem.Acquire(ctx, 1); err != nil {
					log.Printf("WARN [DB REFRESH] Failed to acquire semaphore for %s: %v", k, err)
					atomic.AddUint64(&errorCount, 1) // Count as error if semaphore fails
					return
				}
				defer sem.Release(1)

				// Perform Upstream Query (Use the UpstreamPool's Query method)
				// Re-create the request message to send upstream
				reqMsg := new(dns.Msg)
				reqMsg.SetQuestion(q.Name, q.Qtype)
				reqMsg.RecursionDesired = true
				reqMsg.SetEdns0(4096, s.cfg.DNSSEC) // Add EDNS0 and DO bit based on config

				// log.Printf("DEBUG [DB REFRESH] Re-querying upstream for %s (%s %s)", k, q.Name, dns.TypeToString[q.Qtype])
				replyMsg, upstreamUsed, queryErr := s.upstreamPool.Query(reqMsg)

				// --- Handle Query Result & Update DB ---
				errUpdate := s.db.Update(func(tx *bolt.Tx) error {
					b := tx.Bucket([]byte(cacheBucketName))
					if b == nil {
						return fmt.Errorf("bucket '%s' disappeared", cacheBucketName)
					} // Should not happen

					// Always double-check if the entry still exists and matches before updating/deleting
					// Another process (like handleRequest) could have modified it.
					// This check is simple; more complex logic might involve comparing entry data.
					existingData := b.Get([]byte(k))
					if existingData == nil {
						// log.Printf("DEBUG [DB REFRESH] Entry for key '%s' removed concurrently, skipping update.", k)
						return nil // Entry was deleted, nothing to do
					}
					// Optional: Compare existingData with currentData passed to goroutine for stronger consistency check

					if queryErr != nil {
						log.Printf("WARN [DB REFRESH] Upstream query failed for %s (via %s): %v. Removing expired/failed entry.", k, upstreamUsed, queryErr)
						atomic.AddUint64(&errorCount, 1)
						b.Delete([]byte(k)) // Remove entry if refresh query fails
						atomic.AddUint64(&removedCount, 1)
						return nil // Don't return the query error, just log and delete
					}

					if replyMsg == nil { // Should not happen if queryErr is nil
						log.Printf("ERROR [DB REFRESH] Upstream query for %s returned nil message but no error. Removing entry.", k)
						atomic.AddUint64(&errorCount, 1)
						b.Delete([]byte(k))
						atomic.AddUint64(&removedCount, 1)
						return nil
					}

					// --- Refresh Succeeded - Update Cache Entry ---
					isNegative := replyMsg.Rcode == dns.RcodeNameError // Add other codes? Check your logic
					ttl := s.getEffectiveTTL(replyMsg, isNegative)     // Use server's TTL logic

					if ttl == 0 {
						log.Printf("INFO [DB REFRESH] Refreshed query for %s resulted in TTL 0 (RCODE: %s). Removing entry.", k, dns.RcodeToString[replyMsg.Rcode])
						b.Delete([]byte(k)) // Remove if new TTL is zero
						atomic.AddUint64(&removedCount, 1)
						return nil
					}

					// Pack the new message
					packedMsg, packErr := replyMsg.Pack()
					if packErr != nil {
						log.Printf("ERROR [DB REFRESH] Failed to pack refreshed DNS message for %s: %v. Removing entry.", k, packErr)
						atomic.AddUint64(&errorCount, 1)
						b.Delete([]byte(k)) // Remove if packing fails
						atomic.AddUint64(&removedCount, 1)
						return nil
					}

					// Prepare new CacheEntry
					expiry := time.Now().Add(time.Duration(ttl) * time.Second)
					cacheEntry := CacheEntry{
						Msg:        packedMsg,
						ExpiryTime: expiry,
					}

					jsonData, jsonErr := json.Marshal(cacheEntry)
					if jsonErr != nil {
						log.Printf("ERROR [DB REFRESH] Failed to marshal refreshed cache entry for %s: %v. Removing entry.", k, jsonErr)
						atomic.AddUint64(&errorCount, 1)
						b.Delete([]byte(k)) // Remove if marshalling fails
						atomic.AddUint64(&removedCount, 1)
						return nil
					}

					// Put the updated entry back into the DB
					putErr := b.Put([]byte(k), jsonData)
					if putErr == nil {
						atomic.AddUint64(&updatedCount, 1)
						// log.Printf("[DB REFRESH] Updated entry for %s (%s)", q.Name, dns.TypeToString[q.Qtype]) // Verbose
					} else {
						log.Printf("ERROR [DB REFRESH] Failed to put updated entry '%s': %v", k, putErr)
						atomic.AddUint64(&errorCount, 1)
						// Don't delete here, maybe next refresh cycle will succeed
					}
					return putErr // Return potential DB Put error
				}) // End BoltDB Update Tx

				if errUpdate != nil {
					// Log error from the DB transaction itself
					log.Printf("ERROR [DB REFRESH] DB transaction failed for key '%s': %v", k, errUpdate)
					// Note: errorCount might be incremented inside the Tx and here, depending on failure point. Refine if needed.
					// We already increment error count inside the TX for specific failures.
				}

			}(question, key, v) // Pass question, key, and current value to goroutine
		} // End key iteration

		return nil // Return nil from the View func
	}) // End BoltDB View Tx

	if errView != nil {
		log.Printf("ERROR [DB REFRESH] Failed to initiate cache view: %v", errView)
		atomic.AddUint64(&errorCount, 1) // Count view errors
	}

	// Wait for all potentially spawned refresh goroutines to complete
	wg.Wait()

	duration := time.Since(startTime)
	log.Printf(color.MagentaString("[DB REFRESH] Cycle finished in %v. Processed: %d, Updated: %d, Removed: %d, Errors: %d"),
		duration.Round(time.Millisecond), atomic.LoadUint64(&processedCount), atomic.LoadUint64(&updatedCount), atomic.LoadUint64(&removedCount), atomic.LoadUint64(&errorCount))
}

// ** END PART 8 **
// ** PART 9: Server Shutdown **

// Close cleanly shuts down the server resources.
// Signals background tasks and closes the database.
func (s *Server) Close() error {
	log.Println("Closing server resources...")

	// Signal background tasks (like DB refresher) to stop
	// Check if channel is already closed to prevent panic on double-close
	select {
	case <-s.shutdownChan:
		// Already closed
	default:
		close(s.shutdownChan)
		log.Println("Shutdown signal sent to background tasks.")
	}

	// --- TODO: Add WaitGroup or other mechanism to wait for background tasks ---
	// If startDBRefresher or other tasks need time to finish cleanly after
	// receiving the shutdown signal, implement waiting logic here.
	// time.Sleep(1 * time.Second) // Simple placeholder wait

	log.Println("Closing database...")
	if s.db != nil {
		if err := s.db.Close(); err != nil {
			return fmt.Errorf("failed to close database: %w", err)
		}
		log.Println("Database closed.")
		return nil
	}
	log.Println("Database was already nil.")
	return nil
}

// ** END PART 9 **
// ** PART 10: Main Function **

// (Based closely on your provided main function from pasted-text.txt, page 5)
func main() {
	// --- Command Line Argument Parsing ---
	configPath := flag.String("config", "config.yaml", "Path to the configuration file (YAML)")
	flag.Parse()

	// Use standard log package; coloring handled within specific log calls
	log.SetFlags(log.LstdFlags | log.Lmicroseconds) // Add microseconds for better timing visibility
	log.Printf("INFO: Attempting to load configuration from: %s", *configPath)

	// --- Load Configuration ---
	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("FATAL: Failed to load configuration: %v", err)
	}

	// --- Log Loaded Configuration ---
	log.Println("INFO: Configuration loaded successfully:")
	log.Printf("  -> Listen Address: %s", cfg.ListenIP)
	log.Printf("  -> Listen Port: %d", cfg.ListenPort)
	log.Printf("  -> Database Path: %s", cfg.DBPath)
	log.Printf("  -> Cache TTL (Seconds): %d", cfg.CacheTTL)
	log.Printf("  -> Negative TTL (Seconds): %d", cfg.NegativeTTL)
	log.Printf("  -> DNSSEC Enabled (DO bit): %t", cfg.DNSSEC)
	if cfg.DBRefreshInterval > 0 {
		log.Printf("  -> DB Refresh Interval: %s (%v)", cfg.DBRefreshIntervalString, cfg.DBRefreshInterval)
	} else {
		log.Printf("  -> DB Refresh Interval: %s (Disabled)", cfg.DBRefreshIntervalString)
	}
	log.Printf("  -> Upstream Servers:")
	if len(cfg.Upstreams) > 0 {
		for i, up := range cfg.Upstreams {
			log.Printf("       %d: Name='%s', Address='%s', Type='%s'", i+1, up.Name, up.Address, up.Type)
		}
	} else {
		log.Println("       (No upstreams configured)")
	}
	// Log blocklists if loaded
	// if len(cfg.Blocklists) > 0 { ... }

	// --- Initialize Server ---
	srv, err := NewServer(cfg)
	if err != nil {
		log.Fatalf("FATAL: Failed to initialize server: %v", err)
	}
	// Defer closing server resources (like the DB) on shutdown
	defer func() {
		log.Println("INFO: Initiating deferred server resource close...")
		if err := srv.Close(); err != nil {
			log.Printf("ERROR: Failed to close server resources cleanly: %v", err)
		} else {
			log.Println("INFO: Server resources closed.")
		}
	}()

	// --- Start Background DB Refresher ---
	// This will now use the interval loaded from the config file
	// and respect the shutdown channel.
	srv.startDBRefresher() // Only starts if interval > 0

	// --- Start DNS Listeners ---
	go func() {
		log.Printf("INFO: Starting UDP DNS listener on %s:%d...", cfg.ListenIP, cfg.ListenPort)
		// Use the server's configured address and port
		err := srv.udpServer.ListenAndServe()
		// Log fatal only if the error is not due to server shutting down
		// net.ErrClosed is expected during graceful shutdown
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Fatalf("FATAL: Failed to run UDP listener: %v", err)
		} else if err != nil {
			log.Printf("INFO: UDP listener shut down: %v", err)
		} else {
			log.Println("INFO: UDP listener finished.")
		}
	}()

	go func() {
		log.Printf("INFO: Starting TCP DNS listener on %s:%d...", cfg.ListenIP, cfg.ListenPort)
		err := srv.tcpServer.ListenAndServe()
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Fatalf("FATAL: Failed to run TCP listener: %v", err)
		} else if err != nil {
			log.Printf("INFO: TCP listener shut down: %v", err)
		} else {
			log.Println("INFO: TCP listener finished.")
		}
	}()

	log.Println(color.HiBlueString("INFO: DNS Server is up and running. Listening on %s:%d (UDP/TCP). Press Ctrl+C to exit.", cfg.ListenIP, cfg.ListenPort))

	// --- Graceful Shutdown Handling ---
	sigChan := make(chan os.Signal, 1)
	// Notify on Interrupt (Ctrl+C) and Terminate signals
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Block until a signal is received
	sig := <-sigChan
	log.Printf("INFO: Received signal: %s. Shutting down gracefully...", sig)

	// --- Perform Shutdown Actions ---
	// Shutdown DNS listeners first (allow in-flight requests to finish)
	// Add timeouts if desired (e.g., srv.udpServer.ShutdownContext(ctx))
	log.Println("INFO: Shutting down DNS listeners...")
	shutdownError := false
	if srv.udpServer != nil {
		if err := srv.udpServer.Shutdown(); err != nil {
			log.Printf("ERROR: shutting down UDP server: %v", err)
			shutdownError = true
		} else {
			log.Println("INFO: UDP server shut down.")
		}
	}
	if srv.tcpServer != nil {
		if err := srv.tcpServer.Shutdown(); err != nil {
			log.Printf("ERROR: shutting down TCP server: %v", err)
			shutdownError = true
		} else {
			log.Println("INFO: TCP server shut down.")
		}
	}

	// The deferred srv.Close() will handle database closing and signaling background tasks.

	log.Println(color.HiBlueString("INFO: Shutdown sequence initiated."))
	// The program will exit after the deferred srv.Close() runs.
	if shutdownError {
		log.Println("WARN: Errors occurred during listener shutdown.")
	}
}

// ** END PART 10 **
