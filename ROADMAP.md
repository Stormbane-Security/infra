# Infra Roadmap

## Current State (2026-04-09)

Infrastructure configuration for Stormbane Security.

## Immediate

### CI Runner Infrastructure
- GitHub Actions self-hosted runners for drydock tests
- Docker image cache (reduce pull times for 510+ test scenarios)
- Windows Server VM for AD/Kerberos/SMB testing (12 beacon check IDs)

### Cloud Test Accounts
Needed for beacon's cloud scanner testing:
- AWS test account (S3 bucket scanning, IAM checks, EC2 metadata)
- GCP test project (GCS bucket scanning, cloud functions)
- Azure test subscription (blob storage, AKS)
- DigitalOcean test account (droplet scanning)

### Kubernetes Test Cluster
- kind or k3d cluster for K8s scanner testing
- Kubelet, API server, etcd, dashboard check ID verification
- Istio/Envoy sidecar detection testing

## Medium Term

### Beacon Cloud SaaS Infrastructure
- PostgreSQL for scan history + user accounts
- Redis for job queues + caching
- S3 for report/screenshot storage
- Beacon API server (Go)
- Forecast AI service (Claude API integration)
- Web dashboard (Next.js on stormbane.net)
