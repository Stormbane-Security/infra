package infra

import (
	"testing"
)

func TestRegistryPopulated(t *testing.T) {
	if len(Registry) == 0 {
		t.Fatal("Registry is empty — no technologies registered")
	}
	t.Logf("Technology registry: %d entries (including aliases)", len(Registry))

	// Count unique technologies (not aliases).
	unique := map[Technology]bool{}
	for _, m := range Registry {
		unique[m.ID] = true
	}
	t.Logf("Unique technologies: %d", len(unique))

	if len(unique) < 100 {
		t.Errorf("expected at least 100 unique technologies, got %d", len(unique))
	}
}

func TestResourceRegistryPopulated(t *testing.T) {
	if len(ResourceRegistry) == 0 {
		t.Fatal("ResourceRegistry is empty — no resource types registered")
	}
	t.Logf("Resource registry: %d entries", len(ResourceRegistry))

	if len(ResourceRegistry) < 50 {
		t.Errorf("expected at least 50 resource types, got %d", len(ResourceRegistry))
	}
}

func TestLookup(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"nginx", "NGINX"},
		{"kubernetes", "Kubernetes"},
		{"k8s", "Kubernetes"}, // alias
		{"aws", "Amazon Web Services"},
		{"ethereum", "Ethereum"},
		{"jenkins", "Jenkins"},
		{"prometheus", "Prometheus"},
		{"vault", "HashiCorp Vault"},
		{"docker", "Docker"},
		{"postgresql", "PostgreSQL"},
		{"pg", "PostgreSQL"}, // alias
	}
	for _, tt := range tests {
		m := Lookup(tt.id)
		if m == nil {
			t.Errorf("Lookup(%q) = nil, want %q", tt.id, tt.want)
			continue
		}
		if m.Name != tt.want {
			t.Errorf("Lookup(%q).Name = %q, want %q", tt.id, m.Name, tt.want)
		}
	}
}

func TestLookupResource(t *testing.T) {
	tests := []struct {
		rt   string
		want string
	}{
		{"aws.ec2_instance", "EC2 Instance"},
		{"aws.s3_bucket", "S3 Bucket"},
		{"gcp.gke_cluster", "GKE Cluster"},
		{"gcp.storage_bucket", "Cloud Storage Bucket"},
		{"azure.aks_cluster", "AKS Cluster"},
		{"azure.key_vault", "Key Vault"},
	}
	for _, tt := range tests {
		r := LookupResource(tt.rt)
		if r == nil {
			t.Errorf("LookupResource(%q) = nil, want %q", tt.rt, tt.want)
			continue
		}
		if r.Name != tt.want {
			t.Errorf("LookupResource(%q).Name = %q, want %q", tt.rt, r.Name, tt.want)
		}
	}
}

func TestByCategory(t *testing.T) {
	dbs := ByCategory(CategoryDatabase)
	if len(dbs) < 5 {
		t.Errorf("ByCategory(database) returned %d entries, expected at least 5", len(dbs))
	}
}

func TestByCloud(t *testing.T) {
	aws := ByCloud(AWS)
	if len(aws) < 10 {
		t.Errorf("ByCloud(aws) returned %d entries, expected at least 10", len(aws))
	}
}

func TestAllFingerprints(t *testing.T) {
	fps := AllFingerprints()
	if len(fps) < 80 {
		t.Errorf("AllFingerprints() returned %d rules, expected at least 80", len(fps))
	}
	t.Logf("Fingerprint rules: %d", len(fps))

	// Verify a well-known fingerprint.
	found := false
	for _, fp := range fps {
		if fp.Signal == "header" && fp.Key == "cf-ray" && fp.Field == "cloud_provider" {
			if fp.Value != "cloudflare" {
				t.Errorf("cf-ray fingerprint value = %q, want cloudflare", fp.Value)
			}
			found = true
			break
		}
	}
	if !found {
		t.Error("missing cf-ray → cloudflare fingerprint")
	}

	// Verify value override works (aws-api-gateway → aws_api_gateway).
	for _, fp := range fps {
		if fp.TechID == "aws-api-gateway" && fp.Field == "proxy_type" {
			if fp.Value != "aws_api_gateway" {
				t.Errorf("aws-api-gateway fingerprint value = %q, want aws_api_gateway", fp.Value)
			}
			break
		}
	}
}
