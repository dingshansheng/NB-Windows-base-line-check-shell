#$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
# 脚本开始
# 用户输入名字
$Name = Read-Host -Prompt "请输入您的名字"
# $Name = "丁善胜"

$LogFileName = $Name + ".log"
$LogPath = Join-Path -Path (Get-Location) -ChildPath $LogFileName

# 获取IP地址和用户名
# $IP = (Get-NetIPAddress -AddressFamily IPv4 | Select-Object -First 1).IPAddress
$IP = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notmatch "^127\." -and $_.IPAddress -notmatch "^169\.254\."
} | Select-Object -First 1 -ExpandProperty IPAddress
$Username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# 将结果输出到日志文件
Add-Content -Value "姓名: $Name" -Path $LogPath
Add-Content -Value "IP地址: $IP" -Path $LogPath
Add-Content -Value "用户名: $Username" -Path $LogPath

# 获取系统信息
$CurrentUser = $env:USERNAME
function Write-Separator {
    param (
        [string]$Character = '-',
        [int]$Length = 40,
        [string]$LogPath
    )
    $separator = $Character * $Length
    Add-Content -Value $separator -Path $LogPath
	Add-Content -Value "  " -Path $LogPath
}

Write-Separator -LogPath $LogPath

# 检查安全软件安装情况
$programs = @("360安全卫士", "火绒安全软件", "金山毒霸","文档安全管理系统 客户端")
Add-Content -Value "1，检查安全软件安装情况" -Path $LogPath
foreach ($program in $programs) {
    $isInstalled = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                    HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                                    Where-Object { $_.DisplayName -like "*$program*" }
    if(($isInstalled)){
		Add-Content -Value "$program 已安装" -Path $LogPath
	}
	else
	{
        Add-Content -Value "$program 未安装" -Path $LogPath
    }
}
Write-Separator -LogPath $LogPath

# 检查数据库软件安装情况
$databases = @("SQLite", "PostgreSQL", "MariaDB", "MySQL")
Add-Content -Value "2，检查数据库软件安装情况" -Path $LogPath
foreach ($db in $databases) {
    $isInstalledDb = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                      HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                                      Where-Object { $_.DisplayName -like "*$db*" }
	if ($isInstalledDb) {
        Add-Content -Value "$db 已安装" -Path $LogPath
    } 
	else
	{
        Add-Content -Value "$db 未安装" -Path $LogPath
    }
}
Write-Separator -LogPath $LogPath

# 检查Recent文件夹内容
$recentPath = Join-Path -Path "C:\Users" -ChildPath "$CurrentUser\AppData\Roaming\Microsoft\Windows\Recent"
Add-Content -Value "3，检查Recent文件夹内容" -Path $LogPath
if (Test-Path -Path $recentPath) {
    $recentFiles = Get-ChildItem -Path $recentPath
    foreach ($file in $recentFiles) {
        Add-Content -Value "Recent文件夹包含文件: $($file.FullName)" -Path $LogPath
    }
}
Write-Separator -LogPath $LogPath

# 添加标题到日志文件
Add-Content -Value "4，检查.sql文件和SQL命名的文件/文件夹" -Path $LogPath
# 获取所有的文件系统驱动器
$drives = Get-PSDrive -PSProvider 'FileSystem'
# 对每个文件系统驱动器执行搜索
foreach ($drive in $drives) {
    # 查找所有的.sql文件
    $sqlFiles = Get-ChildItem -Path $drive.Root -Recurse -Filter "*.sql" -ErrorAction SilentlyContinue -File
    foreach ($file in $sqlFiles) {
        Add-Content -Value "找到SQL文件: $($file.FullName)" -Path $LogPath
    }
	Write-Separator -LogPath $LogPath
    # 查找所有命名包含SQL的文件和文件夹
    $sqlNamedItems = Get-ChildItem -Path $drive.Root -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*SQL*" }
    foreach ($item in $sqlNamedItems) {
        Add-Content -Value "找到命名包含SQL的文件/文件夹: $($item.FullName)" -Path $LogPath
    }
	Write-Separator -LogPath $LogPath
}

# 网卡检查
$networkAdapters = Get-NetAdapter 
foreach ($adapter in $networkAdapters) {
    Add-Content -Value "5，所有的网络适配器: $($adapter.Name)" -Path $LogPath
}
Write-Separator -LogPath $LogPath

# 端口扫描
# 定义要扫描的主机和端口
$hostToScan = "127.0.0.1" # 这里是目标主机的 IP 地址
$portsToScan = 21,22,23,80,135,137,138,139,443,445,1433,1434,1521,3389,8080 # 这里列出了您想要扫描的端口
$timeout = 1000 # 超时时间（毫秒）
$LogPath = Join-Path -Path (Get-Location) -ChildPath $LogFileName
Add-Content -Path $LogPath -Value "6，端口扫描"
# 添加初始日志内容
Add-Content -Path $LogPath -Value "开始端口扫描 - 目标: $hostToScan"
# 执行端口扫描
foreach ($port in $portsToScan) {
    try {
        $tcpclient = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpclient.BeginConnect($hostToScan, $port, $null, $null)
        $wait = $asyncResult.AsyncWaitHandle.WaitOne($timeout, $false)
        if ($wait -and $tcpclient.Connected) {
            $result = "端口 $port - 开放"
        } else {
            $result = "端口 $port - 关闭"
        }
    } catch {
        $result = "端口 $port - 错误: $_"
    } finally {
        if ($tcpclient -ne $null) {
            $tcpclient.Close()
        }
    }
    Write-Output $result
    Add-Content -Path $logPath -Value $result
}
# 添加结束日志内容
Add-Content -Path $LogPath -Value "端口扫描完成"
Write-Separator -LogPath $LogPath

# 无线热点状态检查
Add-Content -Path $LogPath -Value "7，开始检查无线热点状态..."
# 运行netsh命令以检查无线热点状态
try {
    $hostedNetworkStatus = netsh wlan show hostednetwork
    Add-Content -Path $LogPath -Value "无线热点状态信息:"
    Add-Content -Path $LogPath -Value $hostedNetworkStatus
    # 分析无线热点状态
    if ($hostedNetworkStatus -match "状态\s+:\s+已启动") {
        Add-Content -Path $LogPath -Value "无线热点当前已开启。"
    } elseif ($hostedNetworkStatus -match "状态\s+:\s+已停止") {
        Add-Content -Path $LogPath -Value "无线热点当前已关闭。"
    } else {
        Add-Content -Path $LogPath -Value "无法确定无线热点状态。"
    }
} catch {
    Add-Content -Path $LogPath -Value "检查无线热点状态时发生错误：$_"
}
# 完成记录日志
Add-Content -Path $LogPath -Value "无线热点状态检查完成。"
Write-Separator -LogPath $LogPath

# 检索已安装的补丁
$hotfixes = Get-HotFix
Add-Content -Path $LogPath -Value "8，已安装的补丁检查。"
# 遍历并记录每个补丁的信息
foreach ($hotfix in $hotfixes) {
    $logEntry = "Patch ID: $($hotfix.HotFixID), Installed On: $($hotfix.InstalledOn), Description: $($hotfix.Description)"
    Add-Content -Path $LogPath -Value $logEntry
}
Add-Content -Path $LogPath -Value "补丁检查完成。"
Write-Separator -LogPath $LogPath

# 查询Chrome版本
Add-Content -Path $LogPath -Value "9，查询Chrome版本"
# 尝试查找 Chrome 可执行文件的路径
$chromePaths = @(
    "C:\Program Files\Google\Chrome\Application\chrome.exe", # 标准路径
    "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" # 32位系统路径
)
# 查找有效的 Chrome 路径
$chromePath = $chromePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($chromePath) {
    # 获取 Chrome 版本信息
    $ChromeVersionInfo = (Get-ItemProperty -Path $chromePath).VersionInfo
    $ChromeVersion = $ChromeVersionInfo.ProductVersion
    $logEntry = "Google Chrome Version: $ChromeVersion found at $chromePath"
} else {
    $logEntry = "Google Chrome executable not found in the standard installation paths."
}
# 输出日志条目到控制台和日志文件
Write-Output $logEntry
Add-Content -Path $LogPath -Value  $logEntry
Write-Separator -LogPath $LogPath

# 获取 'Guest' 用户的状态
Add-Content -Path $LogPath -Value "10，获取 'Guest' 用户的状态"
try {
    $guestUser = Get-LocalUser -Name "Guest"
    if ($guestUser.AccountDisabled) {
        $status = "disabled"
    } else {
        $status = "enabled"
    }
    $result = "The 'Guest' user account is currently $status."
} catch {
    $result = "Error: $_"
}
# 输出结果到控制台
Write-Output $result
# 将结果写入到日志文件
Add-Content -Path $LogPath -Value $result
Write-Separator -LogPath $LogPath

# 共享和远程访问检查
Add-Content -Path $LogPath -Value "11，共享和远程访问检查"
# 获取所有的 SMB 共享
try {
    $smbShares = Get-SmbShare
    foreach ($share in $smbShares) {
        # 获取共享的访问权限
        $shareAccess = Get-SmbShareAccess -Name $share.Name
        $result = "`nShare Name: $($share.Name)`nShare Path: $($share.Path)`nAccess Control List:"
        Add-Content -Path $LogPath -Value $result
        Write-Output $result
        foreach ($access in $shareAccess) {
            $aclEntry = "Account: $($access.AccountName) Access Rights: $($access.AccessRight)"
            Add-Content -Path $LogPath -Value $aclEntry
            Write-Output $aclEntry
        }
    }
} catch {
    $errorMessage = "Error: $_"
    Add-Content -Path $LogPath -Value $errorMessage
    Write-Output $errorMessage
}
Add-Content -Path $LogPath -Value "共享和远程访问检查结束"
Write-Separator -LogPath $LogPath

# 注册表安全检查脚本
Add-Content -Path $LogPath -Value "12，注册表安全检查"
# 定义要检查的注册表项和值信息的列表
$registryChecks = @(
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Key="AutoAdminLogon"; ExpectedValue="0"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Key="HideFileExt"; ExpectedValue="0"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Key="EnableLUA"; ExpectedValue="1"},
    @{Path="HKLM:\System\CurrentControlSet\Control\Terminal Server"; Key="fDenyTSConnections"; ExpectedValue="1"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Key="AutoShareWks"; ExpectedValue="0"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Key="AutoShareServer"; ExpectedValue="0"},
    @{Path="HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell"; Key="ExecutionPolicy"; ExpectedValue="Restricted"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"; Key="EnableFirewall"; ExpectedValue="1"}
)
# 检查每个注册表项和值
foreach ($check in $registryChecks) {
    $currentValue = (Get-ItemProperty -Path $check.Path -ErrorAction SilentlyContinue).$($check.Key)
    if ($currentValue -ne $check.ExpectedValue) {
        $message = "检查失败: 路径 `"$($check.Path)`", 键 `"$($check.Key)`" 的值为 `"$currentValue`" (预期值: `"$($check.ExpectedValue)`")."
        Add-Content -Path $LogPath -Value $message
    }
    else {
        $message = "检查通过: 路径 `"$($check.Path)`", 键 `"$($check.Key)`" 的值符合预期值 `"$($check.ExpectedValue)`"."
        Add-Content -Path $LogPath -Value $message
    }
}
Add-Content -Path $LogPath -Value "注册表安全检查结束"
Write-Separator -LogPath $LogPath

# 查找涉密以及敏感信息文件
Add-Content -Path $LogPath -Value "开始查找涉密以及敏感信息文件"
# 关键词列表
$keywords = '秘密', '机密', '绝密', '密码', '台账', '账号', '身份证', '电话', 'mysql', '1521', '3306'
# 获取所有逻辑驱动器
$drives = Get-PSDrive -PSProvider 'FileSystem'
# 为每个驱动器创建一个后台作业
$jobs = foreach ($drive in $drives) {
    Start-Job -ScriptBlock {
        param($drive, $keywords, $LogPath)
        foreach ($keyword in $keywords) {
            Get-ChildItem -Path $drive.Root -Recurse -File -ErrorAction SilentlyContinue |
            Select-String -Pattern $keyword -ErrorAction SilentlyContinue |
            ForEach-Object {
                # 将匹配的文件信息写入日志文件
                $result = "发现敏感关键词 '$keyword' - 文件: $($_.Path)"
                Add-Content -Path $LogPath -Value $result
            }
        }
    } -ArgumentList $drive, $keywords, $LogPath
}

# 等待所有作业完成
$jobs | Wait-Job
# 收集作业的输出
$jobs | ForEach-Object {
    Receive-Job -Job $_
}
# 清理作业
$jobs | Remove-Job
# 搜索结束，写入日志
Add-Content -Path $LogPath -Value "查找涉密文件结束"
# 输出日志路径
Write-Host "检查已完成。日志文件路径: $LogPath"

