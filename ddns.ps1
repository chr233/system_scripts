param (
    [string]$DnspodToken,
    [string]$DdnsDomain,
    [string[]]$DdnsSubDomains,
    [string] $DnspodBaseAddress = "https://dnsapi.cn/",
    [string] $IpCacheFile = "ip.txt"
)

if ($null -eq $DnspodToken) {
    Write-Error "DnspodToken 参数是必须的";
    exit;
}

if ($null -eq $DdnsDomain) {
    Write-Error 'DdnsDomain 参数是必须的, 例如 "chrxw.cn"';
    exit;
}

if ($null -eq $DdnsSubDomains -or $DdnsSubDomains.Length -eq 0) {
    Write-Error 'DdnsSubDomains 参数是必须的, 例如 "pal" "mc"';
    exit;
}

Set-Location $PSScriptRoot

$date = Get-Date -Format "yyyy.MM.dd"
$logFileName = "log_$date.txt"

# 封装DnspodAPI请求
function DnspodRequest {
    param(
        [string]$Path,
        [Hashtable]$Payload 
    )
    
    if ($null -eq $Payload) {
        $Payload = @{}
    }

    $Payload["login_token"] = $DnspodToken;
    $Payload["format"] = "json";
    $Payload["lang"] = "cn";
    
    $Headers = @{
        "User-Agent" = "curl/7.29.0"
    }
    
    $url = $DnspodBaseAddress + $Path;

    try {
        $response = Invoke-RestMethod -Uri $url -Method Post -Body $Payload -Headers $Headers -ErrorAction Stop;
        if ($null -eq $response -or $null -eq $response.status -or $response.status.code -ne "1") {
            Write-Error $response.status.message;
        }
        return $response;
    }
    catch {
        Write-Error "API ERROR $($_.Exception.Message)`ninfo:`n$($_.Exception.Response.Content)";
    }
}

# 获取域名列表
function GetDomainList {
    $response = DnspodRequest -Path "Domain.List";
    
    if ($null -ne $response) {
        $domains = $response.domains;
        return $domains;
    }
    else {
        Write-Error "获取域名列表出错";
    }
}

# 获取域名解析记录列表
function GetDnsRecord {
    param(
        [int]$DomainId,
        [string]$RecordType = "A"
    )
    
    $payload = @{
        "domain_id"   = $DomainId
        "record_type" = $RecordType
    }
    
    $response = DnspodRequest -Path "Record.List" -Payload $payload;
    
    if ($null -eq $response -or $null -eq $response.status -or $response.status.code -ne "1") {
        Write-Error "获取域名记录列表出错";
    }
    else {
        return $response.records;
    }
}

# 添加Dns记录
function AddDnsRecord {
    param(
        [int]$DomainId,
        [string]$SubDomain,
        [string]$RecordType = "A",
        [int]$RecordLineId = 0,
        [string]$Value,
        [int] $TTL = 600
    )
    
    $data = @{
        "domain_id"      = $DomainId
        "sub_domain"     = $SubDomain
        "record_type"    = $RecordType
        "record_line_id" = $RecordLineId
        "value"          = $Value
        "ttl"            = $TTL
    }
    
    $response = DnspodRequest -Path "Record.Create" -Payload $data;
    
    if ($null -eq $response -or $null -eq $response.status -or $response.status.code -ne "1") {
        Write-Error "添加域名记录出错";
        return $false;
    }
}

# 修改Dns记录
function SetDnsRecord {
    param(
        [int]$DomainId,
        [int]$RecordId,
        [string]$SubDomain,
        [string]$RecordType = "A",
        [int]$RecordLineId = 0,
        [string]$Value,
        [int] $TTL = 600
    )
    
    $data = @{
        "domain_id"      = $DomainId
        "record_id"      = $RecordId
        "sub_domain"     = $SubDomain
        "record_type"    = $RecordType
        "record_line_id" = $RecordLineId
        "value"          = $Value
        "ttl"            = $TTL
    }
    
    $response = DnspodRequest -Path "Record.Modify" -Payload $data;
    
    if ($null -eq $response -or $null -eq $response.status -or $response.status.code -ne "1") {
        Write-Error "修改域名记录出错";
        return $false;
    }
}

# 获取本机IP
function GetIpv4 {
    $Headers = @{
        "User-Agent" = "curl/7.29.0"
    }

    try {
        $response = Invoke-RestMethod -Uri "http://4.ipw.cn/" -Method Get -Headers $Headers -ErrorAction Stop;
        return $response;
    }
    catch {
        Write-Error "API ERROR $($_.Exception.Message)`ninfo:`n$($_.Exception.Response.Content)";
    }
}

# 获取缓存IP
function GetCacheIp {
    if (Test-Path $IpCacheFile) {
        $cacheIp = Get-Content -Path $IpCacheFile;
        return $cacheIp;
    }
    else {
        return $null;
    }
}

# 更新缓存IP
function SetCacheIp {
    param(
        [string]$NewIp
    )

    Set-Content -Path $IpCacheFile -Value $NewIp;
}

# 输出日志
function Write-Log {
    param (
        [string]$Message,
        [bool]$E
    )

    if ($E) {
        Write-Error $Message;
    }
    else {
        Write-Host $Message;
    }

    Add-Content -Path $logFileName -Value $Message -Encoding UTF8
}

# 删除旧的日志
function ClearOldLog {
    $logFiles = Get-ChildItem -Path "log_*.txt" | Sort-Object LastWriteTime
    $count = $logFiles.Count - 10;
    if ($count -ge 0) {
        $filesToDelete = $logFiles[10..($count - 1)];
        foreach ($file in $filesToDelete) {
            Remove-Item -Path $file.FullName -Force;
        }
    }
}

if (Test-Path -Path $logFileName -eq $false) {
    Set-Content -Path $IpCacheFile -Value "";
}

# 检查日志文件数量，如果超过10个，则删除最早的文件

# DDNS脚本
Write-Host "获取当前公网IP";
$currentIp = GetIpv4;

if ($null -eq $currentIp) {
    Write-Error "获取当前公网IP失败";
    exit;
}
else {
    Write-Host "当前公网IP: $currentIp";
}

$oldIp = GetCacheIp;
if ($oldIp -eq $currentIp) {
    Write-Host "公网IP未更改, 无需更新";
    exit;
}
else {
    Write-Log "===$date===";
    Write-Log "检测到公网IP变动 $oldIp -> $currentIp";
    SetCacheIp -NewIp $currentIp;
}

$domain = GetDomainList | Where-Object { $_.name -eq $DdnsDomain };
if ($null -eq $domain) {
    Write-Log "获取域名列表失败或找不到指定域名, 请检查Token是否正常" -E;
    exit;
}

$records = GetDnsRecord -DomainId $domain.id -RecordType "A";
if ($null -eq $records) {
    Write-Log "获取域名 $DdnsDomain 记录列表失败, 请检查Token是否正常" -E;
    continue;
}

foreach ($subName in $DdnsSubDomains.Split(",")) {
    $sub = $subName.Trim();
    $record = $records | Where-Object { $_.name -eq $sub };
    $fullDomain = $sub + "." + $domain.name;
    if ($null -eq $record) {
        # 不存在解析记录, 添加解析记录
        AddDnsRecord -DomainId $domain.id -SubDomain $sub -Value $currentIp;
        Write-Log "新增解析记录 $fullDomain = $currentIp";
    }
    else {
        # 存在解析记录, 更新解析记录
        $recordValue = $records.value;
        if ($recordValue -eq $currentIp) {
            Write-Log "解析记录 $fullDomain = $currentIp 无需更改";
        }
        else {
            SetDnsRecord -DomainId $domain.id -RecordId $record.id -SubDomain $sub -Value $currentIp -RecordLineId $record.line_id;
            Write-Log "修改解析记录 $fullDomain = $recordValue --> $currentIp";
        }
    }
}

ClearOldLog;
Write-Host "DDNS脚本执行完毕"