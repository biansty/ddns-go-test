package dns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

// --- 核心逻辑 ---
func (d *DNSHE) addUpdateDomainRecords(recordType string) {
	ipAddr, domains := d.Domains.GetNewIpResult(recordType)
	if ipAddr == "" {
		return
	}

	for _, domain := range domains {
		fullDomain := domain.GetFullDomain()
		rootDomain, firstPrefix, multiPrefix := splitDomainToMultiLevels(fullDomain)
		if rootDomain == "" {
			util.Log("域名格式非法: %s", fullDomain)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

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

		recordName := multiPrefix
		targetFullName := fullDomain
		if multiPrefix == "" {
			targetFullName = firstSubDomain
			recordName = ""
		}

		existRec, err := d.findRecordByFullName(subID, targetFullName, recordType)
		if err != nil {
			util.Log("查询DNS记录异常: %s", err)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

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

// 拆分域名到多级前缀
func splitDomainToMultiLevels(fullDomain string) (rootDomain, firstPrefix, multiPrefix string) {
	fullDomain = strings.TrimSuffix(fullDomain, ".")
	parts := strings.Split(fullDomain, ".")
	if len(parts) < 2 {
		return "", "", ""
	}

	rootDomain = strings.Join(parts[len(parts)-2:], ".")
	if len(parts) == 2 {
		return rootDomain, "", ""
	}
	if len(parts) == 3 {
		return rootDomain, parts[0], ""
	}

	firstPrefix = parts[len(parts)-3]
	multiPrefix = strings.Join(parts[:len(parts)-3], ".")
	return rootDomain, firstPrefix, multiPrefix
}

// 类型转换工具函数
func convertToInt(v interface{}) (int, error) {
	switch val := v.(type) {
	case int:
		return val, nil
	case string:
		return strconv.Atoi(val)
	case float64:
		return int(val), nil
	default:
		return 0, fmt.Errorf("不支持的类型: %T", v)
	}
}

// 查询/注册一级子域
func (d *DNSHE) getOrRegisterFirstSubdomain(prefix, root string) (int, error) {
	var listResp dnsheListSubdomainsResp
	u := fmt.Sprintf("%s&endpoint=subdomains&action=list", dnsheAPIBase)
	if err := d.request("GET", u, nil, &listResp); err != nil {
		return 0, fmt.Errorf("查询子域名列表失败: %s", err)
	}

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

	if prefix == "" {
		return 0, fmt.Errorf("根域%s未注册", root)
	}
	req := dnsheRegisterReq{Subdomain: prefix, Rootdomain: root}
	var regResp dnsheRegisterResp
	u = fmt.Sprintf("%s&endpoint=subdomains&action=register", dnsheAPIBase)
	if err := d.request("POST", u, req, &regResp); err != nil {
		return 0, fmt.Errorf("注册失败: %s", err)
	}

	subID, err := convertToInt(regResp.SubdomainID)
	if err != nil {
		return 0, fmt.Errorf("subdomain_id 转换失败: %s", err)
	}

	if !regResp.Success || subID <= 0 {
		errMsg := "注册无响应"
		if regResp.Error != "" {
			errMsg = regResp.Error
		}
		return 0, fmt.Errorf("注册一级子域失败: %s", errMsg)
	}
	return subID, nil
}

// 按完整域名查询DNS记录
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
			errMsg = resp.Error
		}
		return nil, fmt.Errorf("查询DNS记录异常: %s", errMsg)
	}

	for _, r := range resp.Records {
		if strings.EqualFold(r.Type, recordType) && strings.EqualFold(r.Name, fullName) {
			return &r, nil
		}
	}
	return nil, nil
}

// 创建带多级前缀的DNS记录
func (d *DNSHE) createRecordWithMultiPrefix(subID int, multiPrefix, recordType, ip string) error {
	req := dnsheCreateRecordReq{
		SubdomainID: subID,
		Type:        recordType,
		Content:     ip,
		Name:        multiPrefix,
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
			errMsg = resp.Error
		}
		return fmt.Errorf("创建DNS记录异常: %s", errMsg)
	}

	switch v := resp.RecordID.(type) {
	case int:
		util.Log("创建记录成功，record_id (int): %d", v)
	case string:
		util.Log("创建记录成功，record_id (string): %s", v)
	default:
		util.Log("创建记录成功，record_id (未知类型): %v", v)
	}
	return nil
}

// 更新DNS记录
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
			errMsg = resp.Error
		}
		return fmt.Errorf("更新DNS记录异常: %s", errMsg)
	}
	return nil
}

// 通用HTTP请求方法
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

	rawBody, _ := io.ReadAll(resp.Body)
	util.Log("API 原始响应: %s", string(rawBody))

	bodyReader := bytes.NewReader(rawBody)
	if err = json.NewDecoder(bodyReader).Decode(result); err != nil {
		util.Log("JSON 反序列化失败: %s, 但 API 可能已执行成功", err)
		return nil
	}
	return nil
}

// 适配原有接口
func (d *DNSHE) findRecordByType(subID int, domain *config.Domain, recordType string) (*dnsheRecord, error) {
	return d.findRecordByFullName(subID, domain.GetFullDomain(), recordType)
}

func (d *DNSHE) createRecord(subID int, recordType, ip string) error {
	return d.createRecordWithMultiPrefix(subID, "", recordType, ip)
}

// --- 扩展功能（可选）---
// GetSubdomainDetail 获取子域名详情
func (d *DNSHE) GetSubdomainDetail(subdomainID int) (*dnsheSubdomainDetailResp, error) {
	var resp dnsheSubdomainDetailResp
	qs := url.Values{}
	qs.Set("subdomain_id", strconv.Itoa(subdomainID))
	u := fmt.Sprintf("%s&endpoint=subdomains&action=get&%s", dnsheAPIBase, qs.Encode())
	if err := d.request("GET", u, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetQuota 查询配额
func (d *DNSHE) GetQuota() (*dnsheQuota, error) {
	var resp dnsheQuotaResp
	u := fmt.Sprintf("%s&endpoint=quota", dnsheAPIBase)
	if err := d.request("GET", u, nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Quota, nil
}
