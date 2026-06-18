// Package fingerprint — nmap -sV 服务版本识别
package fingerprint

import (
	"context"
	"fmt"
	"strings"
	"time"

	log "distributed-scanner/log"

	nmap "github.com/Ullaakut/nmap/v3"
)

type ProbeResult struct {
	URL         string
	Proto       string
	Tags        []string
	RawResponse string
}

var FallbackTags = []string{"exposure", "misconfig", "config"}

func normalizeTag(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, " ", "-")
	return name
}

func NmapProbe(ctx context.Context, host string, port int) (ProbeResult, error) {
	hostPort := fmt.Sprintf("%s:%d", host, port)
	portStr := fmt.Sprintf("%d", port)

	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	scanner, err := nmap.NewScanner(probeCtx,
		nmap.WithTargets(host),
		nmap.WithPorts(portStr),
		nmap.WithServiceInfo(),
		nmap.WithVersionIntensity(5),
		nmap.WithSkipHostDiscovery(),
		nmap.WithDisabledDNSResolution(),
	)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("[nmap-probe] create scanner failed: %w", err)
	}

	result, warnings, err := scanner.Run()
	if warnings != nil {
		for _, w := range *warnings {
			log.Printf("[nmap-probe] warning on %s: %s\n", hostPort, w)
		}
	}
	if err != nil {
		return ProbeResult{}, fmt.Errorf("[nmap-probe] run failed on %s: %w", hostPort, err)
	}

	for _, nmapHost := range result.Hosts {
		for _, p := range nmapHost.Ports {
			if p.State.State != "open" {
				continue
			}

			svcName := strings.ToLower(strings.TrimSpace(p.Service.Name))
			product := strings.TrimSpace(p.Service.Product)
			version := strings.TrimSpace(p.Service.Version)
			extraInfo := strings.TrimSpace(p.Service.ExtraInfo)
			isTunnel := strings.ToLower(strings.TrimSpace(p.Service.Tunnel)) == "ssl"
			proto, url := resolveProtoURL(svcName, isTunnel, hostPort)
			tags := nmapServiceToTags(svcName, product, isTunnel)
			rawResp := fmt.Sprintf(
				"service=%s product=%s version=%s extraInfo=%s tunnel=%v confidence=%d",
				svcName, product, version, extraInfo, isTunnel, p.Service.Confidence,
			)

			log.Printf("[nmap-probe] %s → service=%s product=%s version=%s tags=%v\n",
				hostPort, svcName, product, version, tags)

			return ProbeResult{
				URL:         url,
				Proto:       proto,
				Tags:        tags,
				RawResponse: rawResp,
			}, nil
		}
	}

	log.Printf("[nmap-probe] %s → no service detected, using default tags\n", hostPort)
	return ProbeResult{
		URL:         hostPort,
		Proto:       "tcp",
		Tags:        FallbackTags,
		RawResponse: "nmap: no service detected",
	}, nil
}

func resolveProtoURL(svcName string, isTunnel bool, hostPort string) (proto, url string) {
	if isTunnel || svcName == "https" || strings.Contains(svcName, "ssl") {
		return "https", "https://" + hostPort
	}
	if svcName == "http" || strings.HasPrefix(svcName, "http") {
		return "http", "http://" + hostPort
	}
	return "tcp", hostPort
}

func nmapServiceToTags(svcName, product string, isTunnel bool) []string {
	if svcName == "" || svcName == "unknown" {
		return FallbackTags
	}

	tagSet := make(map[string]bool)

	tagSet[normalizeTag(svcName)] = true

	if product != "" {
		productTag := normalizeTag(product)
		tagSet[productTag] = true
	}

	switch {
	case svcName == "http" || strings.HasPrefix(svcName, "http"):
		tagSet["web"] = true
	case isTunnel || svcName == "https" || strings.Contains(svcName, "ssl"):
		tagSet["http"] = true
		tagSet["ssl"] = true
		tagSet["web"] = true
	case svcName == "ftp", svcName == "sftp":
		tagSet["network"] = true
	case svcName == "mysql", svcName == "postgresql", svcName == "mssql",
		svcName == "oracle-tns", svcName == "ms-sql-s":
		tagSet["database"] = true
	case svcName == "redis", svcName == "memcached", svcName == "mongodb":
		tagSet["database"] = true
	case svcName == "smtp", svcName == "imap", svcName == "pop3":
		tagSet["mail"] = true
	case svcName == "rdp", svcName == "ms-wbt-server":
		tagSet["rdp"] = true
		tagSet["windows"] = true
	case svcName == "ldap", svcName == "ldaps":
		tagSet["ldap"] = true
	case svcName == "smb", svcName == "microsoft-ds", svcName == "netbios-ssn":
		tagSet["smb"] = true
		tagSet["windows"] = true
	}

	tags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}
	return tags
}
