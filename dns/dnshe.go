
package dns

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "net/url"
    "strconv"
    "strings"

    "github.com/jeessy2/ddns-go/v6/config"
    "github.com/jeessy2/ddns-go/v6/util"
)

const defaultDNSHEBase = "https://api005.dnshe.com/index.php?m=domain_hub"

type DNSHE struct {
    DNS     config.DNS
    Domains config.Domains
    TTL     int
    BaseURL string
}

type dnsheSubdomain struct {
    ID         int    `json:"id"`
    Subdomain  string `json:"subdomain"`
    Rootdomain string `json:"rootdomain"`
    FullDomain string `json:"full_domain"`
    Status     string `json:"status"`
}

type dnsheListSubdomainsResp struct {
    Success    bool             `json:"success"`
    Count      int              `json:"count"`
    Subdomains []dnsheSubdomain `json:"subdomains"`
    Error      string           `json:"error,omitempty"`
}

type dnsheRegisterReq struct {
    Subdomain  string `json:"subdomain"`
    Rootdomain string `json:"rootdomain"`
}

type dnsheRegisterResp struct {
    Success     bool   `json:"success"`
    Message     string `json:"message"`
    SubdomainID int    `json:"subdomain_id"`
    FullDomain  string `json:"full_domain"`
    Error       string `json:"error,omitempty"`
}

type dnsheRecord struct {
    ID      int    `json:"id"`
    Name    string `json:"name"`
    Type    string `json:"type"`
    Content string `json:"content"`
    TTL     int    `json:"ttl"`
    Status  string `json:"status"`
}

type dnsheListRecordsResp struct {
    Success bool           `json:"success"`
    Count   int            `json:"count"`
    Records []dnsheRecord  `json:"records"`
    Error   string         `json:"error,omitempty"`
}

type dnsheCreateRecordReq struct {
    SubdomainID int    `json:"subdomain_id"`
    Type        string `json:"type"`
    Content     string `json:"content"`
    TTL         int    `json:"ttl,omitempty"`
}

type dnsheCreateRecordResp struct {
    Success  bool   `json:"success"`
    Message  string `json:"message"`
    RecordID int    `json:"record_id"`
    Error    string `json:"error,omitempty"`
}

type dnsheUpdateRecordReq struct {
    RecordID int    `json:"record_id"`
    Content  string `json:"content,omitempty"`
    TTL      int    `json:"ttl,omitempty"`
}

type dnsheUpdateRecordResp struct {
    Success bool   `json:"success"`
    Message string `json:"message"`
    Error   string `json:"error,omitempty"`
}

func (d *DNSHE) Init(dnsConf *config.DnsConfig, ipv4cache *util.IpCache, ipv6cache *util.IpCache) {
    d.Domains.Ipv4Cache = ipv4cache
    d.Domains.Ipv6Cache = ipv6cache
    d.DNS = dnsConf.DNS
    d.Domains.GetNewIp(dnsConf)

    if dnsConf.TTL == "" {
        d.TTL = 600
    } else {
        ttl, err := strconv.Atoi(dnsConf.TTL)
        if err != nil {
            d.TTL = 600
        } else {
            d.TTL = ttl
        }
    }

    d.BaseURL = defaultDNSHEBase
    if d.DNS.Params != nil {
        if v, ok := d.DNS.Params["baseUrl"]; ok && strings.TrimSpace(v) != "" {
            d.BaseURL = strings.TrimSpace(v)
        }
    }
}

func (d *DNSHE) AddUpdateDomainRecords() config.Domains {
    d.addUpdateDomainRecords("A")
    d.addUpdateDomainRecords("AAAA")
    return d.Domains
}

func (d *DNSHE) addUpdateDomainRecords(recordType string) {
    ipAddr, domains := d.Domains.GetNewIpResult(recordType)
    if ipAddr == "" {
        return
    }
    for _, domain := range domains {
        subID, err := d.ensureSubdomainID(domain)
        if err != nil || subID <= 0 {
            util.Log("查询/注册子域名失败: %s", err)
            domain.UpdateStatus = config.UpdatedFailed
            continue
        }
        existRec, err := d.findRecordByType(subID, domain, recordType)
        if err != nil {
            util.Log("查询 DNS 记录发生异常! %s", err)
            domain.UpdateStatus = config.UpdatedFailed
            continue
        }
        if existRec != nil {
            if existRec.Content == ipAddr {
                util.Log("你的IP %s 没有变化, 域名 %s", ipAddr, domain)
                continue
            }
            if err := d.updateRecord(existRec.ID, ipAddr); err != nil {
                util.Log("更新域名解析 %s 失败! 异常信息: %s", domain, err)
                domain.UpdateStatus = config.UpdatedFailed
                continue
            }
            util.Log("更新域名解析 %s 成功! IP: %s", domain, ipAddr)
            domain.UpdateStatus = config.UpdatedSuccess
        } else {
            if err := d.createRecord(subID, recordType, ipAddr); err != nil {
                util.Log("新增域名解析 %s 失败! 异常信息: %s", domain, err)
                domain.UpdateStatus = config.UpdatedFailed
                continue
            }
            util.Log("新增域名解析 %s 成功! IP: %s", domain, ipAddr)
            domain.UpdateStatus = config.UpdatedSuccess
        }
    }
}

func (d *DNSHE) ensureSubdomainID(domain *config.Domain) (int, error) {
    full := domain.GetFullDomain()
    root := domain.DomainName
    var listResp dnsheListSubdomainsResp
    u := fmt.Sprintf("%s&endpoint=subdomains&action=list", d.BaseURL)
    if err := d.request("GET", u, nil, &listResp); err != nil {
        return 0, err
    }
    if listResp.Success {
        for _, s := range listResp.Subdomains {
            if strings.EqualFold(s.FullDomain, full) {
                return s.ID, nil
            }
        }
    }
    subPrefix := deriveSubPrefix(full, root)
    req := dnsheRegisterReq{Subdomain: subPrefix, Rootdomain: root}
    var regResp dnsheRegisterResp
    u = fmt.Sprintf("%s&endpoint=subdomains&action=register", d.BaseURL)
    if err := d.request("POST", u, req, &regResp); err != nil {
        return 0, err
    }
    if !regResp.Success || regResp.SubdomainID <= 0 {
        if regResp.Error != "" { return 0, fmt.Errorf(regResp.Error) }
        return 0, fmt.Errorf("register subdomain failed")
    }
    return regResp.SubdomainID, nil
}

func deriveSubPrefix(full, root string) string {
    full = strings.TrimSuffix(full, ".")
    root = strings.TrimSuffix(root, ".")
    if strings.EqualFold(full, root) { return "" }
    suf := "." + root
    if strings.HasSuffix(strings.ToLower(full), strings.ToLower(suf)) {
        return full[:len(full)-len(suf)]
    }
    return full
}

func (d *DNSHE) findRecordByType(subID int, domain *config.Domain, recordType string) (*dnsheRecord, error) {
    var resp dnsheListRecordsResp
    qs := url.Values{}
    qs.Set("subdomain_id", strconv.Itoa(subID))
    u := fmt.Sprintf("%s&endpoint=dns_records&action=list&%s", d.BaseURL, qs.Encode())
    if err := d.request("GET", u, nil, &resp); err != nil { return nil, err }
    if !resp.Success { if resp.Error != "" { return nil, fmt.Errorf(resp.Error) }; return nil, nil }
    full := domain.GetFullDomain()
    for _, r := range resp.Records {
        if strings.EqualFold(r.Type, recordType) && strings.EqualFold(r.Name, full) { return &r, nil }
    }
    return nil, nil
}

func (d *DNSHE) createRecord(subID int, recordType, ip string) error {
    req := dnsheCreateRecordReq{SubdomainID: subID, Type: recordType, Content: ip, TTL: d.TTL}
    var resp dnsheCreateRecordResp
    u := fmt.Sprintf("%s&endpoint=dns_records&action=create", d.BaseURL)
    if err := d.request("POST", u, req, &resp); err != nil { return err }
    if !resp.Success { if resp.Error != "" { return fmt.Errorf(resp.Error) }; return fmt.Errorf("create record failed") }
    return nil
}

func (d *DNSHE) updateRecord(recordID int, ip string) error {
    req := dnsheUpdateRecordReq{RecordID: recordID, Content: ip, TTL: d.TTL}
    var resp dnsheUpdateRecordResp
    u := fmt.Sprintf("%s&endpoint=dns_records&action=update", d.BaseURL)
    if err := d.request("POST", u, req, &resp); err != nil { return err }
    if !resp.Success { if resp.Error != "" { return fmt.Errorf(resp.Error) }; return fmt.Errorf("update record failed") }
    return nil
}

func (d *DNSHE) request(method, urlStr string, data interface{}, result interface{}) (err error) {
    jsonBytes := make([]byte, 0)
    if data != nil { jsonBytes, _ = json.Marshal(data) }
    req, err := http.NewRequest(method, urlStr, bytes.NewBuffer(jsonBytes))
    if err != nil { return }
    req.Header.Set("X-API-Key", d.DNS.ID)
    req.Header.Set("X-API-Secret", d.DNS.Secret)
    req.Header.Set("Content-Type", "application/json")
    client := util.CreateHTTPClient()
    resp, err := client.Do(req)
    err = util.GetHTTPResponse(resp, err, result)
    return
}
