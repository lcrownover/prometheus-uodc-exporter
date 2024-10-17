package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

type Target struct {
	Label     *string `yaml:"label"`
	Help      *string `yaml:"help"`
	OID       *string `yaml:"oid"`
	IP        *string `yaml:"ip"`
	Port      int     `yaml:"port"`
	Community string  `yaml:"community"`
	Timeout   int     `yaml:"timeout"`
	Retries   int     `yaml:"retries"`
}

type Config struct {
	Targets  []Target `yaml:"targets"`
	Interval int      `yaml:"interval"`
}

// processConfig ensures that the required values in each target are set correctly
func processConfig(conf *Config) (Config, error) {
	// scrape interval
	if conf.Interval == 0 {
		conf.Interval = 2
	}

	for _, t := range conf.Targets {
		if t.Label == nil {
			return *conf, fmt.Errorf("label is required in target definition")
		}
		if t.Help == nil {
			return *conf, fmt.Errorf("help is required in target definition")
		}
		if t.OID == nil {
			return *conf, fmt.Errorf("oid is required in target definition")
		}
		if t.IP == nil {
			return *conf, fmt.Errorf("ip is required in target definition")
		}
		if t.Port == 0 {
			t.Port = 161
		}
		if t.Community == "" {
			t.Community = "public"
		}
		if t.Timeout == 0 {
			t.Timeout = 2
		}
		if t.Retries == 0 {
			t.Retries = 1
		}
	}
	return *conf, nil
}

func LoadConfig() (*Config, error) {
	var path string
	path, found := os.LookupEnv("UODC_EXPORTER_CONFIG_PATH")
	if !found {
		path = "/etc/prometheus-uodc-exporter/config.yaml"
	}

	slog.Info("Loading configuration", "path", path)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file at %s: %v", path, err)
	}
	var conf Config
	err = yaml.Unmarshal(data, &conf)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal yaml: %v", err)
	}
	conf, err = processConfig(&conf)
	if err != nil {
		return nil, fmt.Errorf("failed to process config: %v", err)
	}
	slog.Debug("config", "struct", fmt.Sprintf("%+v", conf))
	return &conf, nil
}

// GetFloatFromSNMPValue is used to parse the value
// from the SNMP Get because sometimes the float values are
// set as an SNMP STRING type (ugh)
// we may need to eventually make this more generic
// in the event we want to actually return a string
func GetFloatFromSNMPValue(p gosnmp.SnmpPDU) (float64, error) {
	if p.Type == gosnmp.OctetString {
		slog.Debug("snmp value string detected, trying to parse")
		
		v := (p.Value).(string)
		v = strings.TrimSpace(v)
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse float from string: %v", err)
		}
		return f, nil
	}
	// otherwise it should be an int and we convert to float
	f, _ := gosnmp.ToBigInt(p.Value).Float64()
	return f, nil
}

// GetSNMPValue uses a Target definition to get a gauge value via snmp call
func GetSNMPValue(t Target) (float64, error) {
	slog.Debug(
		"getting snmp value",
		"target", *t.IP,
		"port", t.Port,
		"community", t.Community,
		"oid", *t.OID,
		"timeout_seconds", t.Timeout,
	)
	g := &gosnmp.GoSNMP{
		Target:    *t.IP,
		Port:      uint16(t.Port),
		Community: t.Community,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(t.Timeout) * time.Second,
		Retries:   t.Retries,
	}

	err := g.Connect()
	if err != nil {
		return 0, fmt.Errorf("failed to connect to '%s:%d', err: %v", *t.IP, t.Port, err)
	}
	defer g.Conn.Close()

	oids := []string{*t.OID}
	result, err := g.Get(oids)
	if err != nil {
		return 0, fmt.Errorf("failed to get oid '%s', err: %v", *t.OID, err)
	}

	val, _ := GetFloatFromSNMPValue(result.Variables[0])
	slog.Debug("got value", "value", val)
	return val, nil
}

// recordMetrics loops through the Targets, gets the snmp gauge values,
// and sets the value on the corresponding prometheus.Gauge
func recordMetrics(conf Config, gauges map[string]prometheus.Gauge) {
	for {
		for _, target := range conf.Targets {
			val, err := GetSNMPValue(target)
			if err != nil {
				slog.Error("failed to get snmp value", "error", err)
				slog.Debug("fail: setting guage value to 0")
				gauges[*target.Label].Set(0) // delete this in prod
			} else {
				slog.Debug("success: setting guage value", "value", val)
				gauges[*target.Label].Set(val)
			}
		}
		time.Sleep(time.Duration(conf.Interval) * time.Second)
	}
}

// InitGauges generates a map of prometheus.Gauge based on the metric
// label so we can assign values easily.
func InitGauges(conf Config) map[string]prometheus.Gauge {
	slog.Info("Initializing Gauges")
	m := make(map[string]prometheus.Gauge)
	for _, target := range conf.Targets {
		m[*target.Label] = promauto.NewGauge(prometheus.GaugeOpts{
			Name: *target.Label,
			Help: *target.Help,
		})
	}
	return m
}

func main() {
	slog.Info("Starting Prometheus UODC Exporter")

	_, debug := os.LookupEnv("DEBUG")
	logLevel := slog.LevelInfo
	if debug {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})))

	config, err := LoadConfig()
	if err != nil {
		slog.Error("failed to load config", "error", err)
	}

	// initialize all the gauges using the config targets
	gauges := InitGauges(*config)

	// start recording metrics in a gouroutine
	go recordMetrics(*config, gauges)

	// create the registry and register all the guages
	r := prometheus.NewRegistry()
	for _, g := range gauges {
		r.MustRegister(g)
	}

	handler := promhttp.HandlerFor(r, promhttp.HandlerOpts{})

	http.Handle("/metrics", handler)
	log.Fatal(http.ListenAndServe(":12345", nil))
}
