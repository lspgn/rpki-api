package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cloudflare/cfrpki/ov"
	"github.com/cloudflare/gortr/prefixfile"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"sort"
	"strings"

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
	"runtime"
	"strconv"
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

	CacheBin        = flag.String("cache", "https://rpki.cloudflare.com/rpki.json", "URL of the cached JSON data")
	UserAgent       = flag.String("useragent", fmt.Sprintf("%v (+https://github.com/lspgn/rpki-api)", AppVersion), "User-Agent header")
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

func fetchFile(file string, ua string) ([]byte, error) {
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
		req.Header.Set("Accept", "text/json")

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

func processData(res *prefixfile.ROAList) ([]prefixfile.ROAJson, int, int, int) {
	filterDuplicates := make(map[string]bool)

	var count int
	var countv4 int
	var countv6 int

	roalist := make([]prefixfile.ROAJson, 0)
	for _, v := range res.Data {
		_, prefix, _ := net.ParseCIDR(v.Prefix)
		asnStr := v.ASN[2:len(v.ASN)]
		asnInt, _ := strconv.ParseUint(asnStr, 10, 32)
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
		roalist = append(roalist, v)
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
	data, err := fetchFile(file, s.userAgent)
	if err != nil {
		log.Error(err)
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

func (s *state) routineUpdate(file string, interval int) {
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
		err := s.updateFile(file)
		if err != nil {
			switch err.(type) {
			case IdenticalFile:
				log.Info(err)
			default:
				log.Errorf("Error updating: %v", err)
			}
		}
	}
}

func (s *state) prepareOV(res []prefixfile.ROAJson) error {
	vrp := make([]ov.AbstractROA, 0)
	for i := range res {
		vrp = append(vrp, &(res[i]))
	}
	ovData := ov.NewOV(vrp)

	s.ov = ovData
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
	tmpOv := s.ov

	if tmpOv == nil {
		return nil, nil
	}

	return CreateValidationData(tmpOv, prefixStr, asn), nil
}

func (s *state) Resolve(p graphql.ResolveParams) (interface{}, error) {
	s.lock.RLock()
	newlistTmp := s.roalist
	s.lock.RUnlock()

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
			newlist = append(newlist, &(newlistTmp[i]))
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

	lock    *sync.RWMutex
	roalist []prefixfile.ROAJson
	ov      *ov.OriginValidator
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
		lock:      &sync.RWMutex{},
	}

	fieldsQuery := Fields

	fieldsQuery["roas"].Resolve = s.Resolve
	fieldsQuery["validation"].Resolve = s.ResolveValidation

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

	err = s.updateFile(*CacheBin)
	if err != nil {
		switch err.(type) {
		case IdenticalFile:
			log.Info(err)
		default:
			log.Errorf("Error updating: %v", err)
		}
	}
	go s.routineUpdate(*CacheBin, *RefreshInterval)

	err = http.ListenAndServe(*Addr, r)
	if err != nil {
		log.Fatal(err)
	}
}
