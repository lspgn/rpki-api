package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cloudflare/cfrpki/ov"
	"github.com/cloudflare/gortr/prefixfile"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/handler"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	version    = ""
	buildinfos = ""
	AppVersion = "rpki-api " + version + " " + buildinfos

	Addr        = flag.String("addr", ":8080", "Metrics address")
	MetricsPath = flag.String("metrics.path", "/metrics", "Metrics path")
	APIPath     = flag.String("graphql.path", "/api/graphql", "GraphQL path")

	CacheBin  = flag.String("cache", "https://rpki.cloudflare.com/rpki.json", "URL of the cached JSON data")
	MimeType  = flag.String("mime", "application/json", "MIME header")
	UserAgent = flag.String("useragent", fmt.Sprintf("%v (+https://github.com/lspgn/rpki-api)", AppVersion), "User-Agent header")

	BGPEnable             = flag.Bool("bgp", false, "Enable BGP mapping")
	BGPCache              = flag.String("bgp.cache", "./bgp.csv", "URL of the BGP cache (empty to disable)")
	BGPType               = flag.String("bgp.format", "csv", "Format (CSV only)")
	BGPParserCSVHdr       = flag.Bool("bgp.parser.csv.header", true, "Indicates if CSV contains a header ")
	BGPParserCSVPrefix    = flag.Int("bgp.parser.csv.column.prefix", 0, "Column ID for prefix")
	BGPParserCSVASN       = flag.Int("bgp.parser.csv.column.asn", 1, "Column ID for ASN")
	BGPParserCSVSeparator = flag.String("bgp.parser.csv.separator", ",", "CSV separator")

	RefreshInterval = flag.Int("refresh", 600, "Refresh interval in seconds")

	GraphiQL = flag.Bool("graphiql", true, "Enable GraphiQL")
	Pretty   = flag.Bool("pretty", true, "Enable pretty")

	LogLevel = flag.String("loglevel", "info", "Log level")
	Version  = flag.Bool("version", false, "Print version")

	NumberOfROAs = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rpki_roas",
			Help: "Number of ROAS.",
		},
		[]string{"ip_version", "filtered", "path"},
	)
	LastRefresh = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rpki_refresh",
			Help: "Last refresh.",
		},
		[]string{"path"},
	)
	HttpRequestDuration = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "http_query_duration",
			Help:       "Time to complete a query",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"url"},
	)
	HttpRequestCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_query_count",
			Help: "Count of queries",
		},
		[]string{"url"},
	)
)

func initMetrics() {
	prometheus.MustRegister(NumberOfROAs)
	prometheus.MustRegister(LastRefresh)
	prometheus.MustRegister(HttpRequestDuration)
	prometheus.MustRegister(HttpRequestCount)
}

func fetchFile(file string, ua string, mime string) ([]byte, error) {
	var f io.Reader
	var err error
	if len(file) > 8 && (file[0:7] == "http://" || file[0:8] == "https://") {

		// Copying base of DefaultTransport from https://golang.org/src/net/http/transport.go
		// There is a proposal for a Clone of
		tr := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ProxyConnectHeader:    map[string][]string{},
		}
		// Keep User-Agent in proxy request
		tr.ProxyConnectHeader.Set("User-Agent", ua)

		client := &http.Client{Transport: tr}
		req, err := http.NewRequest("GET", file, nil)
		req.Header.Set("User-Agent", ua)
		if mime != "" {
			req.Header.Set("Accept", mime)
		}

		proxyurl, err := http.ProxyFromEnvironment(req)
		if err != nil {
			return nil, err
		}
		proxyreq := http.ProxyURL(proxyurl)
		tr.Proxy = proxyreq

		if err != nil {
			return nil, err
		}

		fhttp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		f = fhttp.Body
	} else {
		f, err = os.Open(file)
		if err != nil {
			return nil, err
		}
	}
	data, err2 := ioutil.ReadAll(f)
	if err2 != nil {
		return nil, err2
	}
	return data, nil
}

func checkFile(data []byte) ([]byte, error) {
	hsum := sha256.Sum256(data)
	return hsum[:], nil
}

func decodeJSON(data []byte) (*prefixfile.ROAList, error) {
	buf := bytes.NewBuffer(data)
	dec := json.NewDecoder(buf)

	var res prefixfile.ROAList
	err := dec.Decode(&res)
	return &res, err
}

func processData(res *prefixfile.ROAList) ([]*prefixfile.ROAJson, int, int, int) {
	filterDuplicates := make(map[string]bool)

	var count int
	var countv4 int
	var countv6 int

	roalist := make([]*prefixfile.ROAJson, 0)
	for i, v := range res.Data {
		_, prefix, _ := net.ParseCIDR(v.Prefix)
		asnInt := v.GetASN()
		asn := uint32(asnInt)

		count++
		if prefix.IP.To4() != nil {
			countv4++
		} else if prefix.IP.To16() != nil {
			countv6++
		}

		key := fmt.Sprintf("%v,%v,%v", prefix, asn, v.Length)
		_, exists := filterDuplicates[key]
		if !exists {
			filterDuplicates[key] = true
		} else {
			continue
		}
		roalist = append(roalist, &(res.Data[i]))
	}
	return roalist, count, countv4, countv6
}

type IdenticalFile struct {
	File string
}

func (e IdenticalFile) Error() string {
	return fmt.Sprintf("File %v is identical to the previous version", e.File)
}

func (s *state) updateFile(file string) error {
	log.Debugf("Refreshing cache from %v", file)
	data, err := fetchFile(file, s.userAgent, s.mime)
	if err != nil {
		return err
	}
	hsum, _ := checkFile(data)
	if s.lasthash != nil {
		cres := bytes.Compare(s.lasthash, hsum)
		if cres == 0 {
			return IdenticalFile{File: file}
		}
	}

	s.lastts = time.Now().UTC()
	s.lastdata = data

	roalistjson, err := decodeJSON(s.lastdata)
	if err != nil {
		return err
	}

	roas, count, countv4, countv6 := processData(roalistjson)
	if err != nil {
		return err
	}
	s.lock.Lock()

	sort.Slice(roas, func(i, j int) bool { return bytes.Compare(roas[i].GetPrefix().IP, roas[j].GetPrefix().IP) < 0 })

	s.roalist = roas
	s.prepareOV(roas)
	s.lock.Unlock()
	log.Infof("New update (%v uniques, %v total prefixes). %v bytes. Updating sha256 hash %x -> %x",
		len(roas), count, len(s.lastconverted), s.lasthash, hsum)
	s.lasthash = hsum

	var countv4_dup int
	var countv6_dup int
	for _, roa := range roas {
		if roa.GetPrefix().IP.To4() != nil {
			countv4_dup++
		} else if roa.GetPrefix().IP.To16() != nil {
			countv6_dup++
		}
	}
	NumberOfROAs.WithLabelValues("ipv4", "filtered", file).Set(float64(countv4))
	NumberOfROAs.WithLabelValues("ipv4", "unfiltered", file).Set(float64(countv4_dup))
	NumberOfROAs.WithLabelValues("ipv6", "filtered", file).Set(float64(countv6))
	NumberOfROAs.WithLabelValues("ipv6", "unfiltered", file).Set(float64(countv6_dup))
	LastRefresh.WithLabelValues(file).Set(float64(s.lastts.UnixNano() / 1e9))

	return nil
}

type BGPRoute struct {
	Prefix net.IP
	ASN    uint32
}

func (s *state) updateFileBGP(file string) error {
	log.Debugf("Refreshing BGP from %v", file)
	data, err := fetchFile(file, s.userAgent, "text/csv")
	if err != nil {
		return err
	}

	rdr := csv.NewReader(bytes.NewBuffer(data))
	csvcomma := s.CSVComma
	if len(csvcomma) > 0 {
		rdr.Comma = rune(csvcomma[0])
	}

	bgpRoutes := make([]*BGPOVResult, 0)

	var itera int64
	var record []string

	regexNonCharacters, err := regexp.Compile("[^0-9]")
	if err != nil {
		return err
	}

	s.ovlock.RLock()
	tmpOv := s.ov
	s.ovlock.RUnlock()

	roaCoversRoute := make(map[*prefixfile.ROAJson]bool)

	for itera = 0; err == nil; itera++ {
		record, err = rdr.Read()

		if (s.CSVHeader && itera == 0) || len(record) == 0 || err != nil {
			continue
		}

		if len(record) <= s.CSVColPrefix {
			log.Errorf("Prefix index %d is above record length %d at line %d, skipping", s.CSVColPrefix, len(record), itera)
			continue
		}

		var prefix *net.IPNet
		prefixStr := record[s.CSVColPrefix]
		_, prefix, err = net.ParseCIDR(prefixStr)
		if err != nil {
			log.Errorf("Could not decode prefix: %s at line %d: %v, skipping", prefixStr, itera, err)
		}

		if len(record) <= s.CSVColASN {
			log.Errorf("ASN index %d is above record length %d at line %d, skipping", s.CSVColASN, len(record), itera)
			continue
		}

		asnStr := record[s.CSVColASN]
		asnR := regexNonCharacters.ReplaceAllString(asnStr, "")
		if asnR == "" {
			log.Errorf("Could not decode AS %s at line %d", asnStr, itera)
			continue
		}
		asnI, _ := strconv.ParseInt(asnR, 10, 64)
		asn := uint32(asnI)
		log.Debugf("Adding BGP route %s %d", prefix, asn)

		r := &BGPOVResult{
			Prefix: prefixStr,
			ASN:    asn,
		}
		if tmpOv != nil {
			ovData := CreateValidationData(tmpOv, prefixStr, asn)
			r.OV = ovData

			for _, v := range ovData.Covering {
				roaCoversRoute[v] = true
				// could double check if the ROA ASN = 0 AND/OR nothing even invalid is covered
			}
		}

		bgpRoutes = append(bgpRoutes, r)

	}
	if err != nil && err != io.EOF {
		return err
	}

	sort.Slice(bgpRoutes, func(i, j int) bool {
		return bytes.Compare(bgpRoutes[i].GetPrefix().IP, bgpRoutes[j].GetPrefix().IP) < 0
	})

	s.bgplock.Lock()
	s.bgplist = bgpRoutes
	s.bgplock.Unlock()

	// Compute ROAs which do not cover any route
	s.lock.RLock()
	roalist := s.roalist
	s.lock.RUnlock()

	missinglist := make([]*prefixfile.ROAJson, 0)
	for _, roa := range roalist {
		if _, ok := roaCoversRoute[roa]; !ok {
			missinglist = append(missinglist, roa)
		}
	}

	s.missinglock.Lock()
	s.missinglist = missinglist
	s.missinglock.Unlock()

	return nil
}

func (s *state) update(file string, fileBGP string) {
	err := s.updateFile(file)
	if err != nil {
		switch err.(type) {
		case IdenticalFile:
			log.Info(err)
		default:
			log.Errorf("Error updating: %v", err)
		}
	}
	if fileBGP != "" {
		err = s.updateFileBGP(fileBGP)
		if err != nil {
			log.Errorf("Error updating BGP: %v", err)
		}
	}
}

func (s *state) routineUpdate(file string, fileBGP string, interval int) {
	log.Debugf("Starting refresh routine (file: %v, interval: %vs)", file, interval)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	for {
		delay := time.NewTimer(time.Duration(interval) * time.Second)
		select {
		case <-delay.C:
		case <-signals:
			log.Debug("Received HUP signal")
		}
		delay.Stop()
		s.update(file, fileBGP)
	}
}

func (s *state) prepareOV(res []*prefixfile.ROAJson) error {
	vrp := make([]ov.AbstractROA, 0)
	for i := range res {
		vrp = append(vrp, res[i])
	}
	ovData := ov.NewOV(vrp)

	s.ovlock.Lock()
	s.ov = ovData
	s.ovlock.Unlock()
	return nil
}

type OVRoute struct {
	Prefix *net.IPNet
	ASN    uint32
}

func (r *OVRoute) GetPrefix() *net.IPNet {
	return r.Prefix
}

func (r *OVRoute) GetASN() uint32 {
	return r.ASN
}

func CreateValidationData(ov *ov.OriginValidator, prefixStr string, asn uint32) OVResult {
	_, prefix, _ := net.ParseCIDR(prefixStr)

	tmpCovering, ovstate, err := ov.Validate(&OVRoute{
		Prefix: prefix,
		ASN:    asn,
	})
	if err != nil {
		log.Error(err)
	}

	covering := make([]*prefixfile.ROAJson, 0)
	for _, m := range tmpCovering {
		mc := m.(*prefixfile.ROAJson)
		covering = append(covering, mc)
	}
	return OVResult{
		State:    ovstate,
		Covering: covering,
	}
}

func (s *state) ResolveValidation(p graphql.ResolveParams) (interface{}, error) {
	prefixStr := p.Args["prefix"].(string)
	asnConv := p.Args["asn"].(float64)
	asn := uint32(asnConv)
	s.ovlock.RLock()
	tmpOv := s.ov
	s.ovlock.RUnlock()

	if tmpOv == nil {
		return nil, nil
	}

	return CreateValidationData(tmpOv, prefixStr, asn), nil
}

func (s *state) ResolveBGP(p graphql.ResolveParams) (interface{}, error) {
	s.bgplock.RLock()
	newlistTmp := s.bgplist
	s.bgplock.RUnlock()

	newlist := make([]*BGPOVResult, 0)

	for i, v := range newlistTmp {
		add := true
		if add && p.Args["asn"] != nil {
			add = false
			if v.ASN == uint32(p.Args["asn"].(float64)) {
				add = true
			}
		}
		if add && p.Args["prefixFilters"] != nil {
			add = false
			tmpAdd, err := MatchResource(v, p.Args)
			if err != nil {
				return nil, err
			}
			add = tmpAdd
		}
		if add && p.Args["status"] != nil {
			add = false
			if v.OV.State == p.Args["status"].(int) {
				add = true
			}
		}

		if add {
			newlist = append(newlist, newlistTmp[i])
		}
	}

	minItem := 0
	if p.Args["offset"] != nil && p.Args["offset"].(int) >= 0 && p.Args["offset"].(int) < len(newlist) {
		minItem = p.Args["offset"].(int)
	}

	maxItem := len(newlist)
	if p.Args["limit"] != nil && p.Args["limit"].(int)+minItem <= len(newlist) {
		maxItem = minItem + p.Args["limit"].(int)
	}

	return newlist[minItem:maxItem], nil

	return nil, nil
}

func (s *state) ResolveRegular(p graphql.ResolveParams) (interface{}, error) {
	return s.Resolve(false, p)
}

func (s *state) ResolveMissing(p graphql.ResolveParams) (interface{}, error) {
	return s.Resolve(true, p)
}

func (s *state) Resolve(missing bool, p graphql.ResolveParams) (interface{}, error) {
	var newlistTmp []*prefixfile.ROAJson
	if missing {
		s.lock.RLock()
		newlistTmp = s.missinglist
		s.lock.RUnlock()
	} else {
		s.lock.RLock()
		newlistTmp = s.roalist
		s.lock.RUnlock()
	}

	newlist := make([]*prefixfile.ROAJson, 0)

	for i, v := range newlistTmp {
		add := true
		if add && p.Args["ta"] != nil {
			add = false
			ta := p.Args["ta"].(string)
			if strings.EqualFold(v.TA, ta) {
				add = true
			}
		}
		if add && p.Args["asn"] != nil {
			add = false
			if v.GetASN() == uint32(p.Args["asn"].(float64)) {
				add = true
			}
		}
		if add && p.Args["prefixFilters"] != nil {
			add = false
			tmpAdd, err := MatchResource(v, p.Args)
			if err != nil {
				return nil, err
			}
			add = tmpAdd
		}

		if add {
			newlist = append(newlist, newlistTmp[i])
		}
	}

	minItem := 0
	if p.Args["offset"] != nil && p.Args["offset"].(int) >= 0 && p.Args["offset"].(int) < len(newlist) {
		minItem = p.Args["offset"].(int)
	}

	maxItem := len(newlist)
	if p.Args["limit"] != nil && p.Args["limit"].(int)+minItem <= len(newlist) {
		maxItem = minItem + p.Args["limit"].(int)
	}

	return newlist[minItem:maxItem], nil
}

type state struct {
	lastdata      []byte
	lastconverted []byte
	lasthash      []byte
	lastts        time.Time
	userAgent     string
	mime          string

	lock    *sync.RWMutex
	roalist []*prefixfile.ROAJson

	missinglock *sync.RWMutex
	missinglist []*prefixfile.ROAJson

	ovlock *sync.RWMutex
	ov     *ov.OriginValidator

	bgplock *sync.RWMutex
	bgplist []*BGPOVResult

	// BGP
	CSVComma     string
	CSVColPrefix int
	CSVColASN    int
	CSVHeader    bool
}

type HandlerFunc interface {
	ContextHandler(ctx context.Context, w http.ResponseWriter, r *http.Request)
}

type TimerHandler struct {
	Handler HandlerFunc
}

func (h TimerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	curUUID := uuid.New().String()
	ctx := r.Context()
	ctx = context.WithValue(ctx, "request.uuid", curUUID)

	label := r.URL.Path

	HttpRequestCount.WithLabelValues(label).Inc()

	start := time.Now().UTC()
	h.Handler.ContextHandler(ctx, w, r)
	end := time.Now().UTC()

	HttpRequestDuration.WithLabelValues(label).Observe(float64(end.Sub(start).Nanoseconds()))
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Parse()
	if *Version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	lvl, _ := log.ParseLevel(*LogLevel)
	log.SetLevel(lvl)

	initMetrics()

	s := state{
		userAgent: *UserAgent,
		mime:      *MimeType,

		lock:        &sync.RWMutex{},
		missinglock: &sync.RWMutex{},
		bgplock:     &sync.RWMutex{},
		ovlock:      &sync.RWMutex{},

		CSVComma:     *BGPParserCSVSeparator,
		CSVHeader:    *BGPParserCSVHdr,
		CSVColPrefix: *BGPParserCSVPrefix,
		CSVColASN:    *BGPParserCSVASN,
	}

	if s.CSVColPrefix < 0 || s.CSVColASN < 0 || s.CSVColASN == s.CSVColPrefix {
		log.Fatal("Error with column indices")
	}

	fieldsQuery := Fields

	fieldsQuery["roas"].Resolve = s.ResolveRegular
	fieldsQuery["validation"].Resolve = s.ResolveValidation
	if *BGPEnable {
		fieldsQuery["bgp"].Resolve = s.ResolveBGP
		fieldsQuery["missing"].Resolve = s.ResolveMissing
	} else {
		delete(fieldsQuery, "bgp")
		delete(fieldsQuery, "missing")
	}

	rootQuery := graphql.ObjectConfig{Name: "query", Fields: fieldsQuery}
	schemaConfig := graphql.SchemaConfig{
		Query: graphql.NewObject(rootQuery),
	}

	schema, err := InitSchema(schemaConfig, log.StandardLogger())
	if err != nil {
		log.Fatal(err)
	}

	h := handler.New(&handler.Config{
		Schema:   schema,
		Pretty:   *Pretty,
		GraphiQL: *GraphiQL,
	})

	th := &TimerHandler{
		Handler: h,
	}

	r := mux.NewRouter()
	r.Handle(*APIPath, th)
	r.Handle(*MetricsPath, promhttp.Handler())

	if !*BGPEnable {
		*BGPCache = ""
	}

	s.update(*CacheBin, *BGPCache)
	go s.routineUpdate(*CacheBin, *BGPCache, *RefreshInterval)

	err = http.ListenAndServe(*Addr, r)
	if err != nil {
		log.Fatal(err)
	}
}
