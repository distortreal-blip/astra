Add-Type -AssemblyName PresentationFramework

$repoRoot = Split-Path $PSScriptRoot -Parent
$logsDir = Join-Path $repoRoot "logs"
if (-not (Test-Path $logsDir)) {
    New-Item -Path $logsDir -ItemType Directory | Out-Null
}
$pidFile = Join-Path $PSScriptRoot ".launcher.pid"

function Stop-Client {
    if (Test-Path $pidFile) {
        $pid = Get-Content $pidFile -ErrorAction SilentlyContinue
        if ($pid) {
            Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
        }
        Remove-Item $pidFile -ErrorAction SilentlyContinue
    } else {
        Get-Process astra-proxy-client -ErrorAction SilentlyContinue | Stop-Process -Force
        Get-Process astra-tun-client -ErrorAction SilentlyContinue | Stop-Process -Force
    }
}

function Ensure-Binary {
    param(
        [string]$binPath,
        [string]$cmdPath
    )
    if (Test-Path $binPath) {
        return $true
    }
    $go = Get-Command go -ErrorAction SilentlyContinue
    if (-not $go) {
        [System.Windows.MessageBox]::Show("Go is not installed, and $binPath is missing.","ASTRA Launcher")
        return $false
    }
    $buildArgs = @("build","-o",$binPath,$cmdPath)
    $p = Start-Process -FilePath $go.Path -ArgumentList $buildArgs -WorkingDirectory $repoRoot -NoNewWindow -PassThru -Wait
    return (Test-Path $binPath)
}

function Start-Client {
    param(
        [string]$name,
        [string]$binPath,
        [string]$configPath
    )
    Stop-Client
    $logOut = Join-Path $logsDir "$name.out.log"
    $logErr = Join-Path $logsDir "$name.err.log"
    $args = @("-config", $configPath)
    $p = Start-Process -FilePath $binPath -ArgumentList $args -WorkingDirectory $repoRoot -NoNewWindow -PassThru -RedirectStandardOutput $logOut -RedirectStandardError $logErr
    Set-Content -Path $pidFile -Value $p.Id
    return $p.Id
}

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="ASTRA Launcher" Height="240" Width="420" WindowStartupLocation="CenterScreen">
  <Grid Margin="12">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
    </Grid.RowDefinitions>
    <TextBlock Text="ASTRA Client Launcher" FontSize="16" FontWeight="Bold" />
    <CheckBox Name="ResetToken" Grid.Row="1" Margin="0,10,0,0" Content="Reset token.dat on start" IsChecked="True"/>
    <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,10,0,0">
      <Button Name="StartProxy" Width="140" Margin="0,0,10,0" Content="Start Proxy"/>
      <Button Name="StartTun" Width="140" Margin="0,0,10,0" Content="Start TUN"/>
      <Button Name="StopClient" Width="80" Content="Stop"/>
    </StackPanel>
    <StackPanel Grid.Row="3" Orientation="Horizontal" Margin="0,10,0,0">
      <Button Name="OpenLogs" Width="140" Content="Open Logs Folder"/>
    </StackPanel>
    <TextBlock Name="Status" Grid.Row="4" Margin="0,12,0,0" Text="Idle" />
  </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

$startProxy = $window.FindName("StartProxy")
$startTun = $window.FindName("StartTun")
$stopClient = $window.FindName("StopClient")
$openLogs = $window.FindName("OpenLogs")
$status = $window.FindName("Status")
$resetToken = $window.FindName("ResetToken")

$startProxy.Add_Click({
    $bin = Join-Path $repoRoot "astra-proxy-client.exe"
    $config = Join-Path $repoRoot "configs\astra-proxy-client.json"
    if (-not (Ensure-Binary -binPath $bin -cmdPath (Join-Path $repoRoot "cmd\astra-proxy-client"))) {
        return
    }
    if ($resetToken.IsChecked) {
        Remove-Item (Join-Path $repoRoot "token.dat") -ErrorAction SilentlyContinue
    }
    $pid = Start-Client -name "astra-proxy-client" -binPath $bin -configPath $config
    $status.Text = "Proxy client started (PID $pid). Proxy: 127.0.0.1:1080"
})

$startTun.Add_Click({
    $bin = Join-Path $repoRoot "astra-tun-client.exe"
    $config = Join-Path $repoRoot "configs\astra-tun-client.json"
    if (-not (Ensure-Binary -binPath $bin -cmdPath (Join-Path $repoRoot "cmd\astra-tun-client"))) {
        return
    }
    if ($resetToken.IsChecked) {
        Remove-Item (Join-Path $repoRoot "token.dat") -ErrorAction SilentlyContinue
    }
    $pid = Start-Client -name "astra-tun-client" -binPath $bin -configPath $config
    $status.Text = "TUN client started (PID $pid). Requires Wintun."
})

$stopClient.Add_Click({
    Stop-Client
    $status.Text = "Stopped."
})

$openLogs.Add_Click({
    Start-Process -FilePath $logsDir
})

$window.ShowDialog() | Out-Null
