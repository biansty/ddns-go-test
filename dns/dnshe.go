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

// 固定 DNSHE API 基址
const dnsheAPIBase = "https://api005.dnshe.com/index.php?m=domain_hub"

type DNSHE struct {
	DNS     config.DNS
	Domains config.Domains
	TTL     int
}

// --- 响应结构体与 API 手册完全对齐 ---
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
	Subdomain  string `json:"subdomain"`  // 一级子域前缀，保留原始字符
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
	Name    string `json:"name"`    // 多级前缀（如555.666）或完整域名
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
	Name        string `json:"name,omitempty"` // 多级前缀（如555.666），保留原始字符
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

// --- 初始化逻辑 ---
func (d *DNSHE) Init(dnsConf *config.DnsConfig, ipv4cache *util.IpCache, ipv6cache *util.IpCache) {
	d.Domains.Ipv4Cache = ipv4cache
	d.Domains.Ipv6Cache = ipv6cache
	d.DNS = dnsConf.DNS
	d.Domains.GetNewIp(dnsConf)

	if dnsConf.TTL == "" {
		d.TTL = 600
	} else {
		ttl, err := strconv.Atoi(dnsConf.TTL)
		d.TTL = 600
		if err == nil {
			d.TTL = ttl
		}
	}
}

func (d *DNSHE) AddUpdateDomainRecords() config.Domains {
	d.addUpdateDomainRecords("A")
	d.addUpdateDomainRecords("AAAA")
	return d.Domains
}

// 核心逻辑：支持多级前缀作为name字段，完全匹配API手册
func (d *DNSHE) addUpdateDomainRecords(recordType string) {
	ipAddr, domains := d.Domains.GetNewIpResult(recordType)
	if ipAddr == "" {
		return
	}

	for _, domain := range domains {
		fullDomain := domain.GetFullDomain()
		// 1. 拆分根域（最后两段）、一级子域前缀、多级子域前缀（均保留原始字符）
		rootDomain, firstPrefix, multiPrefix := splitDomainToMultiLevels(fullDomain)
		if rootDomain == "" {
			util.Log("域名格式非法: %s", fullDomain)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

		// 2. 查询/注册一级子域（lrx.cc.cd，仅一级子域需关联rootdomain）
		firstSubDomain := fmt.Sprintf("%s.%s", firstPrefix, rootDomain)
		if firstPrefix == "" {
			firstSubDomain = rootDomain
		}
		subID, err := d.getOrRegisterFirstSubdomain(firstPrefix, rootDomain)
		if err != nil || subID <= 0 {
			util.Log("一级子域%s查询/注册失败: %s", firstSubDomain, err)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

		// 3. 确定记录name字段：多级前缀（如555.666），无则为空
		recordName := multiPrefix
		targetFullName := fullDomain
		if multiPrefix == "" {
			targetFullName = firstSubDomain
			recordName = ""
		}

		// 4. 查询DNS记录（按完整域名精准匹配）
		existRec, err := d.findRecordByFullName(subID, targetFullName, recordType)
		if err != nil {
			util.Log("查询DNS记录异常: %s", err)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

		// 5. 更新或创建记录（name字段传多级前缀，无过滤）
		if existRec != nil {
			if existRec.Content == ipAddr {
				util.Log("IP未变化: %s -> %s", ipAddr, fullDomain)
				continue
			}
			if err := d.updateRecord(existRec.ID, ipAddr); err != nil {
				util.Log("更新解析%s失败: %s", fullDomain, err)
				domain.UpdateStatus = config.UpdatedFailed
				continue
			}
			util.Log("更新解析%s成功: %s", fullDomain, ipAddr)
			domain.UpdateStatus = config.UpdatedSuccess
		} else {
			if err := d.createRecordWithMultiPrefix(subID, recordName, recordType, ipAddr); err != nil {
				util.Log("新增解析%s失败: %s", fullDomain, err)
				domain.UpdateStatus = config.UpdatedFailed
				continue
			}
			util.Log("新增解析%s成功: %s", fullDomain, ipAddr)
			domain.UpdateStatus = config.UpdatedSuccess
		}
	}
}

// 拆分域名到多级前缀（完全保留原始字符）
// 规则：
// - 根域：最后两段（如cc.cd）
// - 一级前缀：倒数第三段（如lrx）
// - 多级前缀：前面所有段拼接（如555.666.lrx.cc.cd → 555.666）
func splitDomainToMultiLevels(fullDomain string) (rootDomain, firstPrefix, multiPrefix string) {
	fullDomain = strings.TrimSuffix(fullDomain, ".")
	parts := strings.Split(fullDomain, ".")
	if len(parts) < 2 {
		return "", "", "" // 非法域名
	}

	// 根域为最后两段，保留原始字符
	rootDomain = strings.Join(parts[len(parts)-2:], ".")
	if len(parts) == 2 {
		return rootDomain, "", "" // 根域本身，无前缀
	}
	if len(parts) == 3 {
		// 一级子域（lrx.cc.cd）→ 多级前缀为空，一级前缀为第一段
		return rootDomain, parts[0], ""
	}

	// 多级子域：一级前缀为倒数第三段，多级前缀为前面所有段拼接
	firstPrefix = parts[len(parts)-3]
	multiPrefix = strings.Join(parts[:len(parts)-3], ".")
	return rootDomain, firstPrefix, multiPrefix
}

// 查询/注册一级子域（仅一级子域需与rootdomain关联，多级前缀作为记录name）
func (d *DNSHE) getOrRegisterFirstSubdomain(prefix, root string) (int, error) {
	// 1. 查询所有子域名列表
	var listResp dnsheListSubdomainsResp
	u := fmt.Sprintf("%s&endpoint=subdomains&action=list", dnsheAPIBase)
	if err := d.request("GET", u, nil, &listResp); err != nil {
		return 0, fmt.Errorf("查询子域名列表失败: %s", err)
	}

	// 2. 匹配一级子域（按完整域名匹配）
	targetFullDomain := fmt.Sprintf("%s.%s", prefix, root)
	if prefix == "" {
		targetFullDomain = root
	}
	if listResp.Success {
		for _, s := range listResp.Subdomains {
			if strings.EqualFold(s.FullDomain, targetFullDomain) {
				return s.ID, nil
			}
		}
	}

	// 3. 注册一级子域（前缀直接传原始值，无过滤）
	if prefix == "" {
		return 0, fmt.Errorf("根域%s未注册", root)
	}
	req := dnsheRegisterReq{
		Subdomain:  prefix,
		Rootdomain: root,
	}
	var regResp dnsheRegisterResp
	u = fmt.Sprintf("%s&endpoint=subdomains&action=register", dnsheAPIBase)
	if err := d.request("POST", u, req, &regResp); err != nil {
		return 0, fmt.Errorf("注册失败: %s", err)
	}
	if !regResp.Success || regResp.SubdomainID <= 0 {
		errMsg := "注册无响应"
		if regResp.Error != "" {
			errMsg = fmt.Sprintf("注册失败: %s", regResp.Error) // 修复非常量格式字符串
		}
		return 0, fmt.Errorf("注册一级子域失败: %s", errMsg)
	}
	return regResp.SubdomainID, nil
}

// 按完整域名查询DNS记录（支持多级域名匹配）
func (d *DNSHE) findRecordByFullName(subID int, fullName, recordType string) (*dnsheRecord, error) {
	var resp dnsheListRecordsResp
	qs := url.Values{}
	qs.Set("subdomain_id", strconv.Itoa(subID))
	u := fmt.Sprintf("%s&endpoint=dns_records&action=list&%s", dnsheAPIBase, qs.Encode())

	if err := d.request("GET", u, nil, &resp); err != nil {
		return nil, fmt.Errorf("请求失败: %s", err)
	}
	if !resp.Success {
		errMsg := "查询无结果"
		if resp.Error != "" {
			errMsg = fmt.Sprintf("查询DNS记录失败: %s", resp.Error) // 修复非常量格式字符串
		}
		return nil, fmt.Errorf("查询DNS记录异常: %s", errMsg)
	}

	// 严格匹配完整域名（保留原始字符和层级）
	for _, r := range resp.Records {
		if strings.EqualFold(r.Type, recordType) && strings.EqualFold(r.Name, fullName) {
			return &r, nil
		}
	}
	return nil, nil
}

// 创建记录：name字段传多级前缀（如555.666），完全保留原始字符
func (d *DNSHE) createRecordWithMultiPrefix(subID int, multiPrefix, recordType, ip string) error {
	req := dnsheCreateRecordReq{
		SubdomainID: subID,
		Type:        recordType,
		Content:     ip,
		Name:        multiPrefix, // 直接传多级前缀，无任何过滤
		TTL:         d.TTL,
	}
	var resp dnsheCreateRecordResp
	u := fmt.Sprintf("%s&endpoint=dns_records&action=create", dnsheAPIBase)

	if err := d.request("POST", u, req, &resp); err != nil {
		return fmt.Errorf("请求失败: %s", err)
	}
	if !resp.Success {
		errMsg := "创建无响应"
		if resp.Error != "" {
			errMsg = fmt.Sprintf("创建DNS记录失败: %s", resp.Error) // 修复非常量格式字符串
		}
		return fmt.Errorf("创建DNS记录异常: %s", errMsg)
	}
	return nil
}

// --- 其余方法适配多级前缀逻辑 ---
func (d *DNSHE) findRecordByType(subID int, domain *config.Domain, recordType string) (*dnsheRecord, error) {
	return d.findRecordByFullName(subID, domain.GetFullDomain(), recordType)
}

func (d *DNSHE) createRecord(subID int, recordType, ip string) error {
	return d.createRecordWithMultiPrefix(subID, "", recordType, ip)
}

func (d *DNSHE) updateRecord(recordID int, ip string) error {
	req := dnsheUpdateRecordReq{RecordID: recordID, Content: ip, TTL: d.TTL}
	var resp dnsheUpdateRecordResp
	u := fmt.Sprintf("%s&endpoint=dns_records&action=update", dnsheAPIBase)

	if err := d.request("POST", u, req, &resp); err != nil {
		return fmt.Errorf("请求失败: %s", err)
	}
	if !resp.Success {
		errMsg := "更新无响应"
		if resp.Error != "" {
			errMsg = fmt.Sprintf("更新DNS记录失败: %s", resp.Error)
		}
		return fmt.Errorf("更新DNS记录异常: %s", errMsg)
	}
	return nil
}

func (d *DNSHE) request(method, urlStr string, data interface{}, result interface{}) (err error) {
	var reqBody bytes.Buffer
	if method != "GET" && data != nil {
		jsonBytes, marshalErr := json.Marshal(data)
		if marshalErr != nil {
			return fmt.Errorf("序列化失败: %s", marshalErr)
		}
		reqBody = *bytes.NewBuffer(jsonBytes)
	}

	req, err := http.NewRequest(method, urlStr, &reqBody)
	if err != nil {
		return fmt.Errorf("创建请求失败: %s", err)
	}
	req.Header.Set("X-API-Key", d.DNS.ID)
	req.Header.Set("X-API-Secret", d.DNS.Secret)
	req.Header.Set("Content-Type", "application/json")

	client := util.CreateHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败: %s", err)
	}
	defer resp.Body.Close()

	if err = util.GetHTTPResponse(resp, err, result); err != nil {
		return fmt.Errorf("解析响应失败: %s", err)
	}
	return nil
}
