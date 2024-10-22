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
	SnmpVersion int    `yaml:"snmpVersion,omitempty"`
	Label       *string `yaml:"label,omitempty"`
	Help        *string `yaml:"help,omitempty"`
	OID         *string `yaml:"oid,omitempty"`
	IP          *string `yaml:"ip,omitempty"`
	Port        *int    `yaml:"port,omitempty"`
	Community   *string `yaml:"community,omitempty"`
	Timeout     *int    `yaml:"timeout,omitempty"`
	Retries     *int    `yaml:"retries,omitempty"`
	Username    *string `yaml:"username,omitempty"`
	AuthType    *string `yaml:"authType,omitempty"`
	AuthEncrypt *string `yaml:"authEncrypt,omitempty"`
	PrivEncrypt *string `yaml:"privEncrypt,omitempty"`
	AuthPass    *string `yaml:"authPass,omitempty"`
	PrivPass    *string `yaml:"privPass,omitempty"`
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

	for i, t := range conf.Targets {
		switch t.SnmpVersion {
		case 3:
			conf.Targets[i].SnmpVersion = 3
		default:
			conf.Targets[i].SnmpVersion = 2
		}

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
		if t.Port == nil {
			*conf.Targets[i].Port = 161
		}
		if t.Community == nil {
			*conf.Targets[i].Community = "public"
		}
		if t.Timeout == nil {
			*conf.Targets[i].Timeout = 2
		}
		if t.Retries == nil {
			*conf.Targets[i].Retries = 1
		}

		// snmpv3 requires some more stuff
		if t.SnmpVersion == 3 {
			if t.Username == nil {
				return *conf, fmt.Errorf("if using snmpv3, you must set username")
			}
			if t.AuthType == nil {
				return *conf, fmt.Errorf("if using snmpv3, you must set authType")
			}
			if t.AuthEncrypt == nil {
				return *conf, fmt.Errorf("if using snmpv3, you must set authEncrypt")
			}
			if t.PrivEncrypt == nil {
				return *conf, fmt.Errorf("if using snmpv3, you must set privEncrypt")
			}
			if t.AuthPass == nil {
				return *conf, fmt.Errorf("if using snmpv3, you must set authPass")
			}
			if t.PrivPass == nil {
				return *conf, fmt.Errorf("if using snmpv3, you must set privPass")
			}
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

// Sometimes we get strings back from SNMP like "OFF".
// let's normalize those strings then write cases for them
func ConvertSNMPStringKeywordToFloat(s string) (float64, error) {
	slog.Debug("trying to parse known strings", "s", s)
	ns := strings.ToLower(strings.TrimSpace(s))
	switch ns {
	case "off":
		slog.Debug("found preconfigured string, returning value", "s", s, "value", 0)
		return 0, nil
	case "on":
		slog.Debug("found preconfigured string, returning value", "s", s, "value", 1)
		return 1, nil
	}
	return 0, fmt.Errorf("failed to parse string '%s' to float equivalent", s)
}

// ParseFloatFromSNMPValue is used to parse the value
// from the SNMP Get because sometimes the float values are
// set as an SNMP STRING type (ugh)
// we may need to eventually make this more generic
// in the event we want to actually return a string
func ParseFloatFromSNMPValue(p gosnmp.SnmpPDU) (float64, error) {
	slog.Debug("pdu", "pdu", fmt.Sprintf("%+v", p))
	// this is what it usually is, including strings
	if p.Type == gosnmp.OctetString {
		slog.Debug("snmp value string detected, trying to parse")
		v, ok := p.Value.([]byte)
		if !ok {
			return 0, fmt.Errorf("failed to parse string into bytes")
		}
		sv := string(v)
		sv = strings.TrimSpace(sv)
		slog.Debug("value as string", "value", sv)
		// first, we just try to parse the string into a float64
		// usually this is the way it works
		f, err := strconv.ParseFloat(sv, 64)
		if err != nil {
			// sometimes the string is actually a string like "off" or "on"
			// in which case we run it through this conversion function
			// that keeps track of the known keywords and returns a float64
			// if one of them is found
			f, err = ConvertSNMPStringKeywordToFloat(sv)
			if err != nil {
				return 0, fmt.Errorf("failed to parse float from string: %v", err)
			}
		}
		return f, nil
	}
	// otherwise it should be an int and we convert to float
	f, _ := gosnmp.ToBigInt(p.Value).Float64()
	return f, nil
}

// BuildSNMPRequest returns a proper GoSNMP object depending on the
// settings in the config file, such as v2 or v3, etc
func BuildSNMPRequest(t Target) (*gosnmp.GoSNMP, error) {
	// snmp version
	var v gosnmp.SnmpVersion
	switch t.SnmpVersion {
	case 2:
		v = gosnmp.Version2c
	case 3:
		v = gosnmp.Version3
	}

	g := &gosnmp.GoSNMP{
		Target:    *t.IP,
		Port:      uint16(*t.Port),
		Community: *t.Community,
		Version:   v,
		Timeout:   time.Duration(*t.Timeout) * time.Second,
		Retries:   *t.Retries,
	}

	// return it early if we're doing v2
	if v == gosnmp.Version2c {
		slog.Debug("request is version 2")
		return g, nil
	}
	slog.Debug("request is version 3")

	// otherwise continue to build out snmpv3 request

	// auth encrypt type
	var ae gosnmp.SnmpV3AuthProtocol
	switch *t.AuthEncrypt {
	case "SHA":
		ae = gosnmp.SHA
	default:
		return nil, fmt.Errorf("unsupported authEncrypt type: %s", *t.AuthEncrypt)
	}

	// auth encrypt type
	var pe gosnmp.SnmpV3PrivProtocol
	switch *t.PrivEncrypt {
	case "DES":
		pe = gosnmp.DES
	case "AES":
		pe = gosnmp.AES
	default:
		return nil, fmt.Errorf("unsupported authEncrypt type: %s", *t.PrivEncrypt)
	}

	g.SecurityModel = gosnmp.UserSecurityModel
	g.MsgFlags = gosnmp.AuthPriv
	g.SecurityParameters = &gosnmp.UsmSecurityParameters{
		UserName:                 *t.Username,
		AuthenticationProtocol:   ae,
		AuthenticationPassphrase: *t.AuthPass,
		PrivacyProtocol:          pe,
		PrivacyPassphrase:        *t.PrivPass,
	}
	return g, nil
}

// GetSNMPValue uses a Target definition to get a gauge value via snmp call
func GetSNMPValue(t Target) (float64, error) {
	slog.Debug(
		"getting snmp value",
		"label", *t.Label,
		"target", *t.IP,
		"port", t.Port,
		"community", t.Community,
		"oid", *t.OID,
		"timeout_seconds", t.Timeout,
	)
	g, err := BuildSNMPRequest(t)
	if err != nil {
		return 0, fmt.Errorf("failed to build snmp request: %v", err)
	}

	err = g.Connect()
	if err != nil {
		return 0, fmt.Errorf("failed to connect to '%s:%d', err: %v", *t.IP, t.Port, err)
	}
	defer g.Conn.Close()

	oids := []string{*t.OID}
	result, err := g.Get(oids)
	if err != nil {
		return 0, fmt.Errorf("failed to get oid '%s', err: %v", *t.OID, err)
	}

	val, _ := ParseFloatFromSNMPValue(result.Variables[0])
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
