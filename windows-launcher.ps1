# Server Security Monitor v2.0
# Created by FacuSecX
# https://github.com/FacuSecX/
param([ValidateSet('panel','check','install')][string]$Action='panel')
$ErrorActionPreference='Stop'
$panelRoot=$PSScriptRoot
$secretName=$null
$savedSecret=$null
$secretChanged=$false
try {
    $settings=Get-Content -LiteralPath (Join-Path $panelRoot 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $runtimeCandidates=@()
    if ($env:SERVER_MONITOR_NODE) { $runtimeCandidates+=$env:SERVER_MONITOR_NODE }
    if ($settings.PSObject.Properties['nodePath']) { $runtimeCandidates+=$settings.nodePath }
    $installedNode=Get-Command node.exe -ErrorAction SilentlyContinue
    if ($installedNode) { $runtimeCandidates+=$installedNode.Source }
    $nodeRuntime=$runtimeCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
    if (-not $nodeRuntime) { throw 'No se encontro Node.js. Instala Node.js 24 LTS o configura SERVER_MONITOR_NODE.' }
    $launcher=Join-Path $panelRoot 'windows-launcher.mjs'
    $description=& $nodeRuntime $launcher inspect
    if ($LASTEXITCODE -ne 0) { throw 'Revisa la conexion configurada en config.json.' }
    $info=$description | ConvertFrom-Json
    if ($Action -eq 'panel') {
        $health=$null
        try { $health=Invoke-RestMethod ($info.url+'/api/health') -TimeoutSec 3 } catch {}
        if ($health -and $health.app -eq 'storypulse-security') {
            if ([int]$health.version -ge [int]$info.build -and $health.ssh_config_id -eq $info.configId) {
                Write-Host 'El panel ya esta funcionando con esta configuracion.'
                Start-Process $info.url
                exit 0
            }
            $commands=Invoke-RestMethod ($info.url+'/api/commands/status') -TimeoutSec 3
            if ($commands.busy) { throw 'Hay una operacion administrativa en curso. Espera su resultado antes de reiniciar el panel.' }
            $connections=Get-NetTCPConnection -LocalPort ([Uri]$info.url).Port -State Listen -ErrorAction SilentlyContinue
            foreach ($connection in $connections) {
                $owner=Get-CimInstance Win32_Process -Filter ('ProcessId='+$connection.OwningProcess)
                $serverScript=Join-Path $panelRoot 'server.mjs'
                $panelLauncher=Join-Path $panelRoot 'windows-launcher.mjs'
                if ($owner.Name -eq 'node.exe' -and ($owner.CommandLine.Contains($serverScript) -or $owner.CommandLine.Contains($panelLauncher))) {
                    Stop-Process -Id $owner.ProcessId -ErrorAction Stop
                } else { throw 'El puerto esta ocupado por otro proceso. No se cerro automaticamente.' }
            }
            Start-Sleep -Milliseconds 500
        }
    }
    if ($info.authMode -eq 'password') {
        $secretName=$info.passwordEnv
        $savedSecret=[Environment]::GetEnvironmentVariable($secretName,'Process')
        if (-not $savedSecret) {
            Write-Host 'Autenticacion SSH por contrasena. Pageant no se utilizara.'
            $secure=Read-Host 'Contrasena SSH (no se guarda en el proyecto)' -AsSecureString
            $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            try {
                $plain=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
                [Environment]::SetEnvironmentVariable($secretName,$plain,'Process')
                $secretChanged=$true
            } finally {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
                $plain=$null
                $secure.Dispose()
            }
        }
    }
    if ($Action -eq 'panel') { Start-Process $info.url }
    & $nodeRuntime $launcher $Action
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo completar el inicio o la conexion. Revisa los mensajes anteriores.' }
    exit 0
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
} finally {
    if ($secretChanged) { [Environment]::SetEnvironmentVariable($secretName,$savedSecret,'Process') }
}
