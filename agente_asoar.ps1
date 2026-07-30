$WEBHOOK_URL = "http://91.98.126.215:8000/agente"
$INTERVALO_SEGUNDOS = 300

function Obtener-DatosSeguridad {
    $hostname = $env:COMPUTERNAME
    $usuario = $env:USERNAME
    $os = (Get-WmiObject Win32_OperatingSystem).Caption
    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } | Select-Object -First 1).IPAddress

    try {
        $defender = Get-MpComputerStatus
        $defenderActivo = $defender.AntivirusEnabled
        $defenderActualizado = $defender.AntivirusSignatureAge -le 1
    } catch {
        $defenderActivo = $false
        $defenderActualizado = $false
    }

    try {
        $firewall = Get-NetFirewallProfile
        $firewallActivo = ($firewall | Where-Object { $_.Enabled -eq $true }).Count -gt 0
    } catch {
        $firewallActivo = $false
    }

    $actualizacionesPendientes = -1
    $actualizacionesCriticas = -1
    $listaActualizaciones = @()
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $updates = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
        $actualizacionesPendientes = $updates.Updates.Count
        $actualizacionesCriticas = ($updates.Updates | Where-Object { $_.MsrcSeverity -eq "Critical" }).Count
        $listaActualizaciones = @($updates.Updates | ForEach-Object {
            $titulo = ($_.Title -replace '[^\x00-\x7F]', '') -replace '"', "'"
            $kb = if ($_.KBArticleIDs.Count -gt 0) { "KB" + $_.KBArticleIDs[0] } else { "N/A" }
            $sev = if ($_.MsrcSeverity) { $_.MsrcSeverity } else { "Desconocida" }
            [PSCustomObject]@{
                titulo    = $titulo
                kb        = $kb
                severidad = $sev
            }
        })
    } catch {
        $actualizacionesPendientes = -1
        $actualizacionesCriticas = -1
        $listaActualizaciones = @()
    }

    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        if (-not $admins) { $admins = Get-LocalGroupMember -Group "Administradores" -ErrorAction SilentlyContinue }
        $usuariosAdmin = @($admins | ForEach-Object { $_.Name })
    } catch {
        $usuariosAdmin = @()
    }

    try {
        $puertos = @(Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort | Sort-Object -Unique)
    } catch {
        $puertos = @()
    }

    try {
        $cpu = [math]::Round((Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average, 1)
        $ram = Get-WmiObject Win32_OperatingSystem
        $ramUsada = [math]::Round(($ram.TotalVisibleMemorySize - $ram.FreePhysicalMemory) / $ram.TotalVisibleMemorySize * 100, 1)
    } catch {
        $cpu = -1
        $ramUsada = -1
    }

    try {
        $procesosSospechosos = @("mimikatz","meterpreter","netcat","nc","psexec","pwdump","wce","fgdump","gsecdump","procdump","cobaltstrike","beacon","empire","powersploit","nishang","metasploit")
        $procesosActivos = Get-Process | Select-Object Name, Id, CPU, WorkingSet
        $sospechosos = @($procesosActivos | Where-Object {
            $nombre = $_.Name.ToLower()
            $procesosSospechosos | Where-Object { $nombre -like "*$_*" }
        } | ForEach-Object {
            [PSCustomObject]@{ nombre = $_.Name; pid = $_.Id; cpu = [math]::Round($_.CPU, 2); memoria_mb = [math]::Round($_.WorkingSet / 1MB, 2) }
        })
        $todosProcesos = @($procesosActivos | Select-Object -First 20 | ForEach-Object {
            [PSCustomObject]@{ nombre = $_.Name; pid = $_.Id; cpu = [math]::Round($_.CPU, 2); memoria_mb = [math]::Round($_.WorkingSet / 1MB, 2) }
        })
    } catch {
        $sospechosos = @()
        $todosProcesos = @()
    }

    try {
        $eventos = @(Get-EventLog -LogName Security -Newest 10 -ErrorAction SilentlyContinue | ForEach-Object {
            $tipo = switch ($_.EventID) {
                4624 { "Login exitoso" }
                4625 { "Login fallido" }
                4634 { "Logout" }
                4648 { "Login con credenciales explicitas" }
                4720 { "Usuario creado" }
                4726 { "Usuario eliminado" }
                4732 { "Usuario anadido a grupo admin" }
                4756 { "Miembro anadido a grupo" }
                default { "Evento $($_.EventID)" }
            }
            [PSCustomObject]@{
                tiempo  = $_.TimeGenerated.ToString("yyyy-MM-dd HH:mm:ss")
                id      = $_.EventID
                tipo    = $tipo
            }
        })
    } catch {
        $eventos = @()
    }

    try {
        $software = @(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -ne $null } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
            Sort-Object DisplayName |
            Select-Object -First 30 |
            ForEach-Object {
                [PSCustomObject]@{
                    nombre             = $_.DisplayName
                    version            = $_.DisplayVersion
                    publisher          = $_.Publisher
                    fecha_instalacion  = $_.InstallDate
                }
            })
    } catch {
        $software = @()
    }

    $puntuacion = 0
    if ($defenderActivo)          { $puntuacion += 25 }
    if ($defenderActualizado)     { $puntuacion += 20 }
    if ($firewallActivo)          { $puntuacion += 25 }
    if ($actualizacionesCriticas -eq 0) { $puntuacion += 20 }
    if ($usuariosAdmin.Count -le 2)     { $puntuacion += 10 }

    $datos = [PSCustomObject]@{
        hostname            = $hostname
        usuario             = $usuario
        os                  = $os
        ip                  = $ip
        timestamp           = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
        seguridad           = [PSCustomObject]@{
            defender_activo           = $defenderActivo
            defender_actualizado      = $defenderActualizado
            firewall_activo           = $firewallActivo
            actualizaciones_pendientes = $actualizacionesPendientes
            actualizaciones_criticas  = $actualizacionesCriticas
            lista_actualizaciones     = $listaActualizaciones
            usuarios_admin            = $usuariosAdmin
            puertos_escucha           = $puertos
            procesos_sospechosos      = $sospechosos
            todos_procesos            = $todosProcesos
            eventos_seguridad         = $eventos
            software_instalado        = $software
        }
        rendimiento         = [PSCustomObject]@{
            cpu_porcentaje = $cpu
            ram_porcentaje = $ramUsada
        }
        puntuacion_seguridad = $puntuacion
    }
    return $datos
}

function Enviar-Datos($datos) {
    try {
        $json = $datos | ConvertTo-Json -Depth 10 -Compress
        $headers = @{"X-API-Key" = "noctua-2026-secure-key"}
        $response = Invoke-RestMethod -Uri $WEBHOOK_URL -Method POST -Body $json -ContentType "application/json; charset=utf-8" -Headers $headers
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Datos enviados - Puntuacion: $($datos.puntuacion_seguridad)/100"
        return $true
    } catch {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Error: $_"
        return $false
    }
}

Write-Host "ASOAR Agent v1.0 - $env:COMPUTERNAME"
Write-Host "Webhook: $WEBHOOK_URL"

while ($true) {
    $datos = Obtener-DatosSeguridad
    Enviar-Datos $datos
    Start-Sleep -Seconds $INTERVALO_SEGUNDOS
}
