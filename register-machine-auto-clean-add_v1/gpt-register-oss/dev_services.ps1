param(
  [string]$Action = "",
  [string]$Service = "",
  [switch]$Background
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptPath = $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptPath
$RuntimeDir = Join-Path $ProjectRoot "logs/dev-services"
$PidDir = Join-Path $RuntimeDir "pids"
$Services = @("backend", "frontend")

function Ensure-RuntimeDirectories {
  New-Item -ItemType Directory -Force -Path $RuntimeDir | Out-Null
  New-Item -ItemType Directory -Force -Path $PidDir | Out-Null
}

function Show-Usage {
  @"
用法:
  .\dev_services.ps1 fg       前台启动两个服务，按 Ctrl+C 一键关闭
  .\dev_services.ps1 bg       后台启动两个服务
  .\dev_services.ps1 stop     停止由本脚本后台启动的两个服务
  .\dev_services.ps1 restart  重启后台服务
  .\dev_services.ps1 status   查看后台服务状态

说明:
  - 后台模式日志目录: logs/dev-services/
  - 后台模式 PID 目录: logs/dev-services/pids/
"@
}

function Get-ServiceTitle {
  param([Parameter(Mandatory = $true)][string]$Name)

  switch ($Name) {
    "backend" { return "backend" }
    "frontend" { return "frontend" }
    default { return $Name }
  }
}

function Get-ServiceLogFile {
  param([Parameter(Mandatory = $true)][string]$Name)

  Join-Path $RuntimeDir ("{0}.log" -f $Name)
}

function Get-ServicePidFile {
  param([Parameter(Mandatory = $true)][string]$Name)

  Join-Path $PidDir ("{0}.pid" -f $Name)
}

function Resolve-CommandPath {
  param([Parameter(Mandatory = $true)][string[]]$Candidates)

  foreach ($candidate in $Candidates) {
    if ([System.IO.Path]::IsPathRooted($candidate) -and (Test-Path -LiteralPath $candidate)) {
      return $candidate
    }

    $command = Get-Command -Name $candidate -ErrorAction SilentlyContinue
    if ($null -ne $command) {
      return $command.Source
    }
  }

  return $null
}

function Get-HostPowerShell {
  $currentPath = (Get-Process -Id $PID).Path
  if ([string]::IsNullOrWhiteSpace($currentPath)) {
    $currentPath = Resolve-CommandPath @("powershell.exe", "pwsh.exe")
  }

  if ([string]::IsNullOrWhiteSpace($currentPath)) {
    throw "找不到当前 PowerShell 可执行文件。"
  }

  $fileName = [System.IO.Path]::GetFileName($currentPath)
  if ($fileName -ieq "pwsh.exe") {
    return [pscustomobject]@{
      Executable = $currentPath
      Arguments  = @("-NoProfile", "-File")
    }
  }

  return [pscustomobject]@{
    Executable = $currentPath
    Arguments  = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File")
  }
}

function Get-ServiceDefinition {
  param([Parameter(Mandatory = $true)][string]$Name)

  $frontendRoot = Join-Path $ProjectRoot "frontend"

  switch ($Name) {
    "backend" {
      $pythonExe = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
      return [pscustomobject]@{
        Name             = $Name
        Executable       = $pythonExe
        Arguments        = @("api_server.py")
        WorkingDirectory = $ProjectRoot
      }
    }
    "frontend" {
      $viteCmd = Join-Path $frontendRoot "node_modules\.bin\vite.cmd"
      if (Test-Path -LiteralPath $viteCmd) {
        return [pscustomobject]@{
          Name             = $Name
          Executable       = $viteCmd
          Arguments        = @()
          WorkingDirectory = $frontendRoot
        }
      }

      $pnpmExe = Resolve-CommandPath @("pnpm.cmd", "pnpm.exe", "pnpm")
      if ([string]::IsNullOrWhiteSpace($pnpmExe)) {
        throw "缺少前端启动命令: pnpm"
      }

      return [pscustomobject]@{
        Name             = $Name
        Executable       = $pnpmExe
        Arguments        = @("run", "dev")
        WorkingDirectory = $frontendRoot
      }
    }
    default {
      throw ("未知服务: {0}" -f $Name)
    }
  }
}

function Format-ServiceCommand {
  param([Parameter(Mandatory = $true)]$Definition)

  $parts = @($Definition.Executable) + @($Definition.Arguments)
  ($parts | ForEach-Object {
    if ($_ -match "\s") {
      '"{0}"' -f $_
    }
    else {
      $_
    }
  }) -join " "
}

function Require-Dependencies {
  $null = Get-HostPowerShell

  $backendPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
  if (-not (Test-Path -LiteralPath $backendPython)) {
    throw ("缺少 Python 解释器: {0}" -f $backendPython)
  }

  $frontendRoot = Join-Path $ProjectRoot "frontend"
  if (-not (Test-Path -LiteralPath $frontendRoot)) {
    throw ("缺少前端目录: {0}" -f $frontendRoot)
  }

  $null = Get-ServiceDefinition "frontend"
}

function Test-PidRunning {
  param([Parameter(Mandatory = $true)][int]$ProcessId)

  $null -ne (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)
}

function Get-ServicePid {
  param([Parameter(Mandatory = $true)][string]$Name)

  $pidFile = Get-ServicePidFile $Name
  if (-not (Test-Path -LiteralPath $pidFile)) {
    return $null
  }

  $rawPid = (Get-Content -LiteralPath $pidFile -Raw).Trim()
  if ([string]::IsNullOrWhiteSpace($rawPid)) {
    return $null
  }

  try {
    return [int]$rawPid
  }
  catch {
    return $null
  }
}

function Clear-StalePid {
  param([Parameter(Mandatory = $true)][string]$Name)

  $pidFile = Get-ServicePidFile $Name
  if (-not (Test-Path -LiteralPath $pidFile)) {
    return
  }

  $servicePid = Get-ServicePid $Name
  if ($null -eq $servicePid -or -not (Test-PidRunning $servicePid)) {
    Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
  }
}

function Test-ServiceRunning {
  param([Parameter(Mandatory = $true)][string]$Name)

  $servicePid = Get-ServicePid $Name
  if ($null -eq $servicePid) {
    return $false
  }

  Test-PidRunning $servicePid
}

function Stop-ProcessTree {
  param([Parameter(Mandatory = $true)][int]$ProcessId)

  if (-not (Test-PidRunning $ProcessId)) {
    return
  }

  & taskkill /PID $ProcessId /T /F | Out-Null
}

function Stop-ServiceProcess {
  param([Parameter(Mandatory = $true)][string]$Name)

  Clear-StalePid $Name

  $servicePid = Get-ServicePid $Name
  if ($null -eq $servicePid) {
    return
  }

  if (-not (Test-PidRunning $servicePid)) {
    Remove-Item -LiteralPath (Get-ServicePidFile $Name) -Force -ErrorAction SilentlyContinue
    return
  }

  Write-Host ("停止 {0,-12} pid={1}" -f (Get-ServiceTitle $Name), $servicePid)
  Stop-ProcessTree $servicePid

  $deadline = (Get-Date).AddSeconds(10)
  while ((Get-Date) -lt $deadline) {
    if (-not (Test-PidRunning $servicePid)) {
      break
    }
    Start-Sleep -Milliseconds 250
  }

  Remove-Item -LiteralPath (Get-ServicePidFile $Name) -Force -ErrorAction SilentlyContinue
}

function Ensure-NoManagedServicesRunning {
  $busy = $false

  foreach ($service in $Services) {
    Clear-StalePid $service
    if (Test-ServiceRunning $service) {
      $servicePid = Get-ServicePid $service
      Write-Error ("{0,-12} 已在运行 pid={1}，请先执行 .\dev_services.ps1 stop" -f (Get-ServiceTitle $service), $servicePid)
      $busy = $true
    }
  }

  if ($busy) {
    throw "已有托管服务正在运行。"
  }
}

function Write-LogHeader {
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)]$Definition
  )

  $logFile = Get-ServiceLogFile $Name
  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Add-Content -Path $logFile -Value "" -Encoding UTF8
  Add-Content -Path $logFile -Value ("[{0}] starting {1}" -f $timestamp, (Get-ServiceTitle $Name)) -Encoding UTF8
  Add-Content -Path $logFile -Value ("[{0}] command: {1}" -f $timestamp, (Format-ServiceCommand $Definition)) -Encoding UTF8
}

function Convert-CommandOutput {
  param($Value)

  if ($null -eq $Value) {
    return $null
  }

  if ($Value -is [System.Management.Automation.ErrorRecord]) {
    return $Value.ToString()
  }

  return [string]$Value
}

function Run-ServiceProcess {
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [switch]$BackgroundMode
  )

  Ensure-RuntimeDirectories
  $definition = Get-ServiceDefinition $Name
  $logFile = Get-ServiceLogFile $Name

  if (-not $BackgroundMode) {
    Set-Content -Path $logFile -Value $null -Encoding UTF8
  }

  Write-LogHeader -Name $Name -Definition $definition
  Set-Location -LiteralPath $definition.WorkingDirectory

  try {
    & $definition.Executable @($definition.Arguments) 2>&1 |
      ForEach-Object {
        $line = Convert-CommandOutput $_
        if ($null -eq $line) {
          return
        }

        Add-Content -Path $logFile -Value $line -Encoding UTF8

        if (-not $BackgroundMode) {
          Write-Host ("[{0}] {1}" -f (Get-ServiceTitle $Name), $line)
        }
      }

    if ($null -ne $LASTEXITCODE) {
      exit ([int]$LASTEXITCODE)
    }

    exit 0
  }
  catch {
    $message = $_.Exception.Message
    Add-Content -Path $logFile -Value $message -Encoding UTF8
    if (-not $BackgroundMode) {
      Write-Host ("[{0}] {1}" -f (Get-ServiceTitle $Name), $message)
    }
    exit 1
  }
}

function Start-ServiceBackground {
  param([Parameter(Mandatory = $true)][string]$Name)

  $hostPowerShell = Get-HostPowerShell
  $logFile = Get-ServiceLogFile $Name
  Set-Content -Path $logFile -Value $null -Encoding UTF8

  $arguments = @($hostPowerShell.Arguments + @($ScriptPath, "__runservice", $Name, "-Background"))
  $process = Start-Process -FilePath $hostPowerShell.Executable -ArgumentList $arguments -WorkingDirectory $ProjectRoot -WindowStyle Hidden -PassThru

  Set-Content -Path (Get-ServicePidFile $Name) -Value $process.Id -Encoding ASCII
  Start-Sleep -Seconds 1

  if (Test-PidRunning $process.Id) {
    Write-Host ("启动 {0,-12} 成功 pid={1} log={2}" -f (Get-ServiceTitle $Name), $process.Id, $logFile)
    return
  }

  Write-Error ("启动 {0} 失败，最近日志:" -f (Get-ServiceTitle $Name))
  if (Test-Path -LiteralPath $logFile) {
    Get-Content -Path $logFile -Tail 20 | ForEach-Object { Write-Host $_ }
  }
  Remove-Item -LiteralPath (Get-ServicePidFile $Name) -Force -ErrorAction SilentlyContinue
  throw ("启动 {0} 失败。" -f (Get-ServiceTitle $Name))
}

function Start-Background {
  Ensure-RuntimeDirectories
  Require-Dependencies
  Ensure-NoManagedServicesRunning

  $started = @()
  try {
    foreach ($service in $Services) {
      Start-ServiceBackground $service
      $started += $service
    }
  }
  catch {
    foreach ($startedService in $started) {
      Stop-ServiceProcess $startedService
    }
    throw
  }

  Write-Host ""
  Write-Host "后台服务已启动。"
  Write-Host "停止命令: .\dev_services.ps1 stop"
  Write-Host "状态命令: .\dev_services.ps1 status"
}

function Show-Status {
  Ensure-RuntimeDirectories

  foreach ($service in $Services) {
    Clear-StalePid $service

    $title = Get-ServiceTitle $service
    $logFile = Get-ServiceLogFile $service

    if (Test-ServiceRunning $service) {
      $servicePid = Get-ServicePid $service
      Write-Host ("{0,-12} running  pid={1,-8} log={2}" -f $title, $servicePid, $logFile)
    }
    else {
      Write-Host ("{0,-12} stopped  pid={1,-8} log={2}" -f $title, "-", $logFile)
    }
  }
}

function Stop-Background {
  Ensure-RuntimeDirectories

  foreach ($service in $Services) {
    Stop-ServiceProcess $service
  }
}

function Stop-ForegroundProcesses {
  param([Parameter(Mandatory = $true)][object[]]$ManagedProcesses)

  if ($ManagedProcesses.Count -eq 0) {
    return
  }

  Write-Host ""
  Write-Host "正在关闭前台服务..."

  foreach ($managed in $ManagedProcesses) {
    $process = $managed.Process
    if ($null -eq $process) {
      continue
    }

    $process.Refresh()
    if ($process.HasExited) {
      continue
    }

    Stop-ProcessTree $process.Id
  }
}

function Start-ForegroundService {
  param([Parameter(Mandatory = $true)][string]$Name)

  $hostPowerShell = Get-HostPowerShell
  $arguments = @($hostPowerShell.Arguments + @($ScriptPath, "__runservice", $Name))

  Write-Host ("启动 {0,-12} 前台模式" -f (Get-ServiceTitle $Name))
  $process = Start-Process -FilePath $hostPowerShell.Executable -ArgumentList $arguments -WorkingDirectory $ProjectRoot -NoNewWindow -PassThru

  [pscustomobject]@{
    Service = $Name
    Process = $process
  }
}

function Start-Foreground {
  Ensure-RuntimeDirectories
  Require-Dependencies
  Ensure-NoManagedServicesRunning

  $managedProcesses = @()

  try {
    foreach ($service in $Services) {
      $managedProcesses += Start-ForegroundService $service
    }

    Write-Host ""
    Write-Host "两个服务已进入前台托管模式。按 Ctrl+C 可一键关闭。"

    while ($true) {
      foreach ($managed in $managedProcesses) {
        $process = $managed.Process
        $process.Refresh()

        if (-not $process.HasExited) {
          continue
        }

        $exitCode = $process.ExitCode
        Write-Host ""
        Write-Host ("{0} 已退出，退出码={1}，其余服务也会一并关闭。" -f (Get-ServiceTitle $managed.Service), $exitCode)
        return $exitCode
      }

      Start-Sleep -Seconds 1
    }
  }
  finally {
    Stop-ForegroundProcesses $managedProcesses
  }
}

Ensure-RuntimeDirectories

switch ($Action) {
  "__runservice" {
    Run-ServiceProcess -Name $Service -BackgroundMode:$Background
    break
  }
  "fg" {
    exit (Start-Foreground)
  }
  "bg" {
    Start-Background
    break
  }
  "stop" {
    Stop-Background
    break
  }
  "restart" {
    Stop-Background
    Start-Background
    break
  }
  "status" {
    Show-Status
    break
  }
  "help" {
    Show-Usage
    break
  }
  "" {
    Show-Usage
    break
  }
  default {
    Write-Error ("未知命令: {0}" -f $Action)
    Write-Host ""
    Show-Usage
    exit 1
  }
}
