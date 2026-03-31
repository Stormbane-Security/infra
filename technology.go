package infra

import (
	"embed"
	"fmt"
	"io/fs"

	"gopkg.in/yaml.v3"
)

// Technology is a canonical identifier for any piece of infrastructure.
// Format: lowercase, hyphen-separated (e.g., "cloud-run", "next-js").
// These are stable identifiers — once assigned, they never change.
type Technology string

// Category classifies a Technology into its functional role.
type Category string

const (
	CategoryPlatform   Category = "platform"   // where workloads run
	CategoryServer     Category = "server"      // HTTP servers, reverse proxies, load balancers
	CategoryFramework  Category = "framework"   // application frameworks
	CategoryDatabase   Category = "database"    // data stores (SQL, NoSQL, cache, search)
	CategoryAuth       Category = "auth"        // authentication and identity systems
	CategoryCloud      Category = "cloud"       // cloud providers
	CategoryCICD       Category = "cicd"        // CI/CD platforms and runners
	CategoryMessaging  Category = "messaging"   // message brokers and event streaming
	CategoryMonitoring Category = "monitoring"  // observability, logging, alerting
	CategoryCDN        Category = "cdn"         // content delivery networks
	CategoryRuntime    Category = "runtime"     // language runtimes (PHP, Node, Python, Java)
	CategoryContainer  Category = "container"   // container runtimes and orchestrators
	CategoryWeb3       Category = "web3"        // blockchain, wallets, DeFi
	CategorySecurity   Category = "security"    // security tools (WAF, IDS, vault)
	CategoryGateway    Category = "gateway"     // API gateways
)

// InfraLayer describes the network-layer role of a technology.
type InfraLayer string

const (
	LayerCDNEdge      InfraLayer = "cdn_edge"
	LayerAPIGateway   InfraLayer = "api_gateway"
	LayerLoadBalancer InfraLayer = "load_balancer"
	LayerServiceMesh  InfraLayer = "service_mesh"
	LayerReverseProxy InfraLayer = "reverse_proxy"
	LayerOrigin       InfraLayer = "origin"
)

// TechMeta holds metadata about a technology. This is the central
// registry entry — everything Beacon and Drydock need to know about
// a technology in one place.
type TechMeta struct {
	// ID is the canonical identifier (e.g., "nginx", "next-js", "gke").
	ID Technology `yaml:"id"`

	// Name is the human-readable display name (e.g., "NGINX", "Next.js", "GKE").
	Name string `yaml:"name"`

	// Category is the primary functional classification.
	Category Category `yaml:"category"`

	// Layer is the infrastructure layer (only set for server/proxy/CDN types).
	Layer InfraLayer `yaml:"layer,omitempty"`

	// Vendor is the company or project that maintains this technology.
	Vendor string `yaml:"vendor,omitempty"`

	// CloudProvider is set when this technology is specific to a cloud provider.
	// Empty for cloud-agnostic technologies.
	CloudProvider Technology `yaml:"cloud_provider,omitempty"`

	// OpenSource indicates whether this is an open-source project.
	OpenSource bool `yaml:"open_source,omitempty"`

	// DefaultPorts lists the TCP ports this technology typically listens on.
	DefaultPorts []int `yaml:"default_ports,omitempty"`

	// DockerImage is the canonical container image (e.g., "nginx:latest").
	// Used by Drydock for container-based scenarios.
	DockerImage string `yaml:"docker_image,omitempty"`

	// HelmChart is the canonical Helm chart reference (e.g., "bitnami/nginx").
	// Used by Drydock for Kubernetes-based scenarios.
	HelmChart string `yaml:"helm_chart,omitempty"`

	// Aliases are alternative names that map to this technology
	// (e.g., "node" → "nodejs", "pg" → "postgresql").
	Aliases []string `yaml:"aliases,omitempty"`

	// Tags are free-form labels for filtering (e.g., "managed", "serverless", "oss").
	Tags []string `yaml:"tags,omitempty"`

	// Fingerprints are detection rules for identifying this technology
	// from external signals (HTTP headers, response bodies, paths, DNS CNAMEs, etc.).
	// Used by Beacon's fingerprint engine.
	Fingerprints []Fingerprint `yaml:"fingerprints,omitempty"`
}

// Fingerprint is a single detection rule that maps an observable signal
// to a technology identification. When the signal matches during a scan,
// the technology's ID is assigned to the specified evidence field.
type Fingerprint struct {
	// Signal is the type of observable: "header", "server", "body", "path",
	// "cookie", "cname", "title", "dns_suffix", "asn_org".
	Signal string `yaml:"signal"`

	// Key is the header name (only used when Signal is "header").
	Key string `yaml:"key,omitempty"`

	// Match is the case-insensitive substring to look for in the signal value.
	// Empty means presence-only matching (e.g., header exists regardless of value).
	Match string `yaml:"match,omitempty"`

	// Field is the evidence field to set when this rule fires:
	// "proxy_type", "cloud_provider", "framework", "auth_system",
	// "backend_services", "infra_layer".
	Field string `yaml:"field"`

	// Value overrides the technology ID as the value assigned to Field.
	// When empty, the enclosing technology's ID is used.
	Value string `yaml:"value,omitempty"`

	// Confidence is how certain we are that this signal identifies the technology (0.0–1.0).
	Confidence float64 `yaml:"confidence"`
}

// Registry is the global technology catalog. All technologies known to the
// Stormbane ecosystem are registered here. Beacon uses this for fingerprint
// matching; Drydock uses it for scenario validation and image resolution.
var Registry = map[Technology]*TechMeta{}

// techFile is the YAML wrapper for a list of technologies.
type techFile struct {
	Technologies []TechMeta `yaml:"technologies"`
}

//go:embed data/technologies/*.yaml
var techFS embed.FS

func init() {
	if err := loadTechnologies(); err != nil {
		panic("infra: " + err.Error())
	}
}

func loadTechnologies() error {
	return fs.WalkDir(techFS, "data/technologies", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := techFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		var f techFile
		if err := yaml.Unmarshal(data, &f); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		for i := range f.Technologies {
			m := &f.Technologies[i]
			Register(m)
		}
		return nil
	})
}

// Register adds a technology to the global registry.
// Panics on duplicate IDs (catches mistakes at init time).
func Register(m *TechMeta) {
	if _, exists := Registry[m.ID]; exists {
		panic("infra: duplicate technology ID: " + string(m.ID))
	}
	Registry[m.ID] = m
	for _, alias := range m.Aliases {
		if _, exists := Registry[Technology(alias)]; exists {
			panic("infra: alias collides with existing ID: " + alias)
		}
		Registry[Technology(alias)] = m
	}
}

// Lookup returns the TechMeta for a given ID or alias, or nil if not found.
func Lookup(id string) *TechMeta {
	return Registry[Technology(id)]
}

// ByCategory returns all technologies in a given category.
func ByCategory(cat Category) []*TechMeta {
	seen := map[Technology]bool{}
	var result []*TechMeta
	for _, m := range Registry {
		if m.Category == cat && !seen[m.ID] {
			seen[m.ID] = true
			result = append(result, m)
		}
	}
	return result
}

// ByCloud returns all technologies specific to a cloud provider.
func ByCloud(provider Technology) []*TechMeta {
	seen := map[Technology]bool{}
	var result []*TechMeta
	for _, m := range Registry {
		if m.CloudProvider == provider && !seen[m.ID] {
			seen[m.ID] = true
			result = append(result, m)
		}
	}
	return result
}

// FlatFingerprint is a fully resolved fingerprint rule with the technology ID baked in.
// This is the format Beacon's fingerprint engine consumes directly.
type FlatFingerprint struct {
	TechID     Technology
	Signal     string
	Key        string
	Match      string
	Field      string
	Value      string
	Confidence float64
}

// AllFingerprints returns every fingerprint rule across all registered technologies
// as a flat list ready for Beacon's rule engine. Value defaults to the technology ID
// unless overridden in the rule.
func AllFingerprints() []FlatFingerprint {
	seen := map[Technology]bool{}
	var out []FlatFingerprint
	for _, m := range Registry {
		if seen[m.ID] {
			continue
		}
		seen[m.ID] = true
		for _, fp := range m.Fingerprints {
			val := fp.Value
			if val == "" {
				val = string(m.ID)
			}
			out = append(out, FlatFingerprint{
				TechID:     m.ID,
				Signal:     fp.Signal,
				Key:        fp.Key,
				Match:      fp.Match,
				Field:      fp.Field,
				Value:      val,
				Confidence: fp.Confidence,
			})
		}
	}
	return out
}

// Well-known technology constants for use in Go code.
const (
	AWS          Technology = "aws"
	GCP          Technology = "gcp"
	Azure        Technology = "azure"
	Cloudflare   Technology = "cloudflare"
	Vercel       Technology = "vercel"
	Netlify      Technology = "netlify"
	Heroku       Technology = "heroku"
	DigitalOcean Technology = "digitalocean"
	Linode       Technology = "linode"
	Hetzner      Technology = "hetzner"
	OCI          Technology = "oci"
	Fly          Technology = "fly"
	Railway      Technology = "railway"
	Render       Technology = "render"

	Nginx     Technology = "nginx"
	Apache    Technology = "apache"
	Caddy     Technology = "caddy"
	Traefik   Technology = "traefik"
	Envoy     Technology = "envoy"
	HAProxy   Technology = "haproxy"
	Kong      Technology = "kong"

	Docker     Technology = "docker"
	Kubernetes Technology = "kubernetes"
	K3s        Technology = "k3s"

	PostgreSQL    Technology = "postgresql"
	MySQL         Technology = "mysql"
	Redis         Technology = "redis"
	Elasticsearch Technology = "elasticsearch"
	MongoDB       Technology = "mongodb"
	Kafka         Technology = "kafka"

	NextJS  Technology = "next-js"
	Rails   Technology = "rails"
	Django  Technology = "django"
	Spring  Technology = "spring"
	Laravel Technology = "laravel"
	Express Technology = "express"

	Prometheus Technology = "prometheus"
	Grafana    Technology = "grafana"

	Vault    Technology = "vault"
	Keycloak Technology = "keycloak"
	Okta     Technology = "okta"

	Ethereum Technology = "ethereum"
	Bitcoin  Technology = "bitcoin"
	Solana   Technology = "solana"
)
