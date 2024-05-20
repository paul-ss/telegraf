//go:generate ../../../tools/readme_config_includer/generator
package yandex_cloud_monitoring

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/telegraf/internal"
	"github.com/influxdata/telegraf/plugins/outputs"
	"github.com/influxdata/telegraf/selfstat"
)

//go:embed sample.conf
var sampleConfig string

// YandexCloudMonitoring allows publishing of metrics to the Yandex Cloud Monitoring custom metrics
// service
type YandexCloudMonitoring struct {
	Timeout     config.Duration `toml:"timeout"`
	EndpointURL string          `toml:"endpoint_url"`
	Service     string          `toml:"service"`
	CAPath      string          `toml:"ca_path"`

	Log telegraf.Logger

	MetadataTokenURL       string `toml:"metadata_token_url"`
	MetadataFolderURL      string
	FolderID               string `toml:"folder_id"`
	IAMToken               string
	IamTokenExpirationTime time.Time

	client *http.Client

	timeFunc func() time.Time

	MetricOutsideWindow selfstat.Stat
}

type yandexCloudMonitoringMessage struct {
	TS      string                        `json:"ts,omitempty"`
	Labels  map[string]string             `json:"labels,omitempty"`
	Metrics []yandexCloudMonitoringMetric `json:"metrics"`
}

type yandexCloudMonitoringMetric struct {
	Name       string            `json:"name"`
	Labels     map[string]string `json:"labels"`
	MetricType string            `json:"type,omitempty"` // DGAUGE|IGAUGE|COUNTER|RATE. Default: DGAUGE
	TS         string            `json:"ts,omitempty"`
	Value      float64           `json:"value"`
}

type MetadataIamToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

const (
	defaultRequestTimeout = time.Second * 20
	defaultEndpointURL    = "https://monitoring.api.cloud.yandex.net/monitoring/v2/data/write"
	//nolint:gosec // G101: Potential hardcoded credentials - false positive
	defaultMetadataTokenURL  = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
	defaultMetadataFolderURL = "http://169.254.169.254/computeMetadata/v1/yandex/folder-id"
)

func (*YandexCloudMonitoring) SampleConfig() string {
	return sampleConfig
}

// Connect initializes the plugin and validates connectivity
func (a *YandexCloudMonitoring) Connect() error {
	if a.Timeout <= 0 {
		a.Timeout = config.Duration(defaultRequestTimeout)
	}
	if a.EndpointURL == "" {
		a.EndpointURL = defaultEndpointURL
	}
	if a.Service == "" {
		a.Service = "custom"
	}
	if a.MetadataTokenURL == "" {
		a.MetadataTokenURL = defaultMetadataTokenURL
	}
	if a.MetadataFolderURL == "" {
		a.MetadataFolderURL = defaultMetadataFolderURL
	}

	tlsConf, err := commonTLSConfig(a.CAPath)
	if err != nil {
		a.Log.Errorf("Connect: error while fetching TLS config: %s", err)
		return err
	}

	a.client = &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: tlsConf,
		},
		Timeout: time.Duration(a.Timeout),
	}

	if a.FolderID == "" {
		var err error
		a.Log.Info("Folder id was not specified, trying to get it from metadata")
		a.FolderID, err = a.getFolderIDFromMetadata()
		if err != nil {
			return err
		}
	}

	a.Log.Infof("Writing to Yandex.Cloud Monitoring URL: %s", a.EndpointURL)

	tags := map[string]string{}
	a.MetricOutsideWindow = selfstat.Register("yandex_cloud_monitoring", "metric_outside_window", tags)

	return nil
}

// Close shuts down an any active connections
func (a *YandexCloudMonitoring) Close() error {
	a.client = nil
	return nil
}

// Write writes metrics to the remote endpoint
func (a *YandexCloudMonitoring) Write(metrics []telegraf.Metric) error {
	var yandexCloudMonitoringMetrics []yandexCloudMonitoringMetric
	for _, m := range metrics {
		yandexCloudMonitoringMetrics = append(
			yandexCloudMonitoringMetrics,
			a.processMetric(m)...,
		)
	}

	var body []byte
	jsonBytes, err := json.Marshal(
		yandexCloudMonitoringMessage{
			Metrics: yandexCloudMonitoringMetrics,
		},
	)

	if err != nil {
		return err
	}
	body = append(jsonBytes, '\n')
	return a.send(body)
}

func (a *YandexCloudMonitoring) processMetric(tgMetric telegraf.Metric) []yandexCloudMonitoringMetric {
	name := tgMetric.Name()
	metricType := tgMetricTypeToMonitoring(tgMetric.Type())
	ts := tgMetric.Time().Format(time.RFC3339)

	tags := make(map[string]string)
	for _, tag := range tgMetric.TagList() {
		tags[processName(tag.Key)] = tag.Value
	}

	useMetricName := len(tgMetric.FieldList()) == 1
	var res []yandexCloudMonitoringMetric
	for _, field := range tgMetric.FieldList() {
		value, err := internal.ToFloat64(field.Value)
		if err != nil {
			a.Log.Errorf("Skipping value: %v", err)
			continue
		}

		tgMetric.Type()

		res = append(res, yandexCloudMonitoringMetric{
			Name:       getMetricName(name, field.Key, useMetricName),
			Labels:     tags,
			MetricType: metricType,
			TS:         ts,
			Value:      value,
		})
	}

	return res
}

func getMetricName(metricName, fieldName string, useMetricName bool) (name string) {
	if metricName == "" {
		name = fieldName
	} else if useMetricName {
		name = metricName
	} else {
		name = fmt.Sprintf("%s.%s", metricName, fieldName)
	}

	return processName(name)
}

func processName(name string) string {
	return strings.ReplaceAll(name, " ", "_")
}

func tgMetricTypeToMonitoring(t telegraf.ValueType) string {
	switch t {
	case telegraf.Counter, telegraf.Histogram:
		return "COUNTER"
	default:
		return "DGAUGE"
	}
}

func commonTLSConfig(caPath string) (*tls.Config, error) {
	if caPath == "" {
		return &tls.Config{}, nil
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		rootCAs = x509.NewCertPool()
	}

	pemData, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	rootCAs.AppendCertsFromPEM(pemData)
	return &tls.Config{
		MinVersion: tls.VersionTLS10,
		RootCAs:    rootCAs,
	}, nil
}

func getResponseFromMetadata(c *http.Client, metadataURL string) ([]byte, error) {
	req, err := http.NewRequest("GET", metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 || resp.StatusCode < 200 {
		return nil, fmt.Errorf("unable to fetch instance metadata: [%s] %d",
			metadataURL, resp.StatusCode)
	}
	return body, nil
}

func (a *YandexCloudMonitoring) getFolderIDFromMetadata() (string, error) {
	a.Log.Infof("Getting folder ID in %s", a.MetadataFolderURL)
	body, err := getResponseFromMetadata(a.client, a.MetadataFolderURL)
	if err != nil {
		return "", err
	}
	folderID := string(body)
	if folderID == "" {
		return "", fmt.Errorf("unable to fetch folder id from URL %s: %w", a.MetadataFolderURL, err)
	}
	return folderID, nil
}

func (a *YandexCloudMonitoring) getIAMTokenFromMetadata() (string, int, error) {
	a.Log.Debugf("Getting new IAM token in %s", a.MetadataTokenURL)
	body, err := getResponseFromMetadata(a.client, a.MetadataTokenURL)
	if err != nil {
		return "", 0, err
	}
	var metadata MetadataIamToken
	if err := json.Unmarshal(body, &metadata); err != nil {
		return "", 0, err
	}
	if metadata.AccessToken == "" || metadata.ExpiresIn == 0 {
		return "", 0, fmt.Errorf("unable to fetch authentication credentials %s: %w", a.MetadataTokenURL, err)
	}
	return metadata.AccessToken, int(metadata.ExpiresIn), nil
}

func (a *YandexCloudMonitoring) send(body []byte) error {
	req, err := http.NewRequest("POST", a.EndpointURL, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	q := req.URL.Query()
	q.Add("folderId", a.FolderID)
	q.Add("service", a.Service)
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Content-Type", "application/json")
	isTokenExpired := !a.IamTokenExpirationTime.After(time.Now())
	if a.IAMToken == "" || isTokenExpired {
		token, expiresIn, err := a.getIAMTokenFromMetadata()
		if err != nil {
			return err
		}
		a.IamTokenExpirationTime = time.Now().Add(time.Duration(expiresIn) * time.Second)
		a.IAMToken = token
	}
	req.Header.Set("Authorization", "Bearer "+a.IAMToken)

	a.Log.Debugf("Sending metrics to %s", req.URL.String())
	a.Log.Debugf("body: %s", body)
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("failed to write batch: [%v] %s", resp.StatusCode, resp.Status)
	}

	return nil
}

func init() {
	outputs.Add("yandex_cloud_monitoring", func() telegraf.Output {
		return &YandexCloudMonitoring{
			timeFunc: time.Now,
		}
	})
}
