$WEBHOOK_URL = "http://91.98.126.215:8000/agente"
$INTERVALO_SEGUNDOS = 300
$API_KEY = $env:NOCTUA_API_KEY

function Obtener-DatosSeguridad {
    $hostname = $env:COMPUTERNAME
    $usuario  = $env:USERNAME
    $os       = (Get-WmiObject Win32_OperatingSystem).Caption
    $ip       = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } | Select-Object -First 1).IPAddress

    # Windows Defender
    try {
        $defender           = Get-MpComputerStatus
        $defenderActivo     = $defender.AntivirusEnabled
        $defenderActualizado = $defender.AntivirusSignatureAge -le 1
    } catch {
        $defenderActivo     = $false
        $defenderActualizado = $false
    }

    # Firewall
    try {
        $firewall       = Get-NetFirewallProfile
        $firewallActivo = ($firewall | Where-Object { $_.Enabled -eq $true }).Count -gt 0
    } catch {
        $firewallActivo = $false
    }

    # Actualizaciones
    $actualizacionesPendientes = -1
    $actualizacionesCriticas   = -1
    $listaActualizaciones      = @()
    try {
        $updateSession          = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher         = $updateSession.CreateUpdateSearcher()
        $updates                = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
        $actualizacionesPendientes = $updates.Updates.Count
        $actualizacionesCriticas   = ($updates.Updates | Where-Object { $_.MsrcSeverity -eq "Critical" }).Count
        $listaActualizaciones = @($updates.Updates | ForEach-Object {
            $titulo = ($_.Title -replace '[^\x00-\x7F]', '') -replace '"', "'"
            $kb     = if ($_.KBArticleIDs.Count -gt 0) { "KB" + $_.KBArticleIDs[0] } else { "N/A" }
            $sev    = if ($_.MsrcSeverity) { $_.MsrcSeverity } else { "Desconocida" }
            [PSCustomObject]@{ titulo = $titulo; kb = $kb; severidad = $sev }
        })
    } catch {
        $actualizacionesPendientes = -1
        $actualizacionesCriticas   = -1
        $listaActualizaciones      = @()
    }

    # Administradores
    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        if (-not $admins) { $admins = Get-LocalGroupMember -Group "Administradores" -ErrorAction SilentlyContinue }
        $usuariosAdmin = @($admins | ForEach-Object { $_.Name })
    } catch {
        $usuariosAdmin = @()
    }

    # Puertos con telemetria de proceso
    try {
        $puertos = @(Get-NetTCPConnection -State Listen | Where-Object {
            $_.LocalPort -lt 10000 -and $_.LocalPort -notin @(135,139,445,5040)
        } | ForEach-Object {
            $conn = $_
            try {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    puerto     = $conn.LocalPort
                    proceso    = if ($proc) { $proc.Name } else { "Sistema" }
                    pid        = $conn.OwningProcess
                    cpu        = if ($proc) { [math]::Round($proc.CPU, 1) } else { 0 }
                    memoria_mb = if ($proc) { [math]::Round($proc.WorkingSet64 / 1MB, 1) } else { 0 }
                }
            } catch {
                [PSCustomObject]@{ puerto = $conn.LocalPort; proceso = "Desconocido"; pid = 0; cpu = 0; memoria_mb = 0 }
            }
        } | Sort-Object puerto)
    } catch {
        $puertos = @()
    }

    # CPU y RAM
    try {
        $cpu     = [math]::Round((Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average, 1)
        $ram     = Get-WmiObject Win32_OperatingSystem
        $ramUsada = [math]::Round(($ram.TotalVisibleMemorySize - $ram.FreePhysicalMemory) / $ram.TotalVisibleMemorySize * 100, 1)
    } catch {
        $cpu      = -1
        $ramUsada = -1
    }

    # Procesos sospechosos
    try {
        $procesosSospechosos = @("mimikatz","meterpreter","netcat","nc.exe","psexec","pwdump","wce","fgdump","gsecdump","procdump","cobaltstrike","beacon","empire","powersploit","nishang","metasploit")
        $procesosActivos     = Get-Process | Select-Object Name, Id, CPU, WorkingSet
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
        $sospechosos   = @()
        $todosProcesos = @()
    }

    # Eventos de seguridad
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
            [PSCustomObject]@{ tiempo = $_.TimeGenerated.ToString("yyyy-MM-dd HH:mm:ss"); id = $_.EventID; tipo = $tipo }
        })
    } catch {
        $eventos = @()
    }

    # Software instalado
    try {
        $software = @(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -ne $null } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
            Sort-Object DisplayName |
            Select-Object -First 30 |
            ForEach-Object {
                [PSCustomObject]@{
                    nombre            = $_.DisplayName
                    version           = $_.DisplayVersion
                    publisher         = $_.Publisher
                    fecha_instalacion = $_.InstallDate
                }
            })
    } catch {
        $software = @()
    }

    # Puntuacion de seguridad
    $puntuacion = 0
    if ($defenderActivo)               { $puntuacion += 25 }
    if ($defenderActualizado)          { $puntuacion += 20 }
    if ($firewallActivo)               { $puntuacion += 25 }
    if ($actualizacionesCriticas -eq 0) { $puntuacion += 20 }
    if ($usuariosAdmin.Count -le 2)    { $puntuacion += 10 }

    $datos = [PSCustomObject]@{
        hostname  = $hostname
        usuario   = $usuario
        os        = $os
        ip        = $ip
        timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
        seguridad = [PSCustomObject]@{
            defender_activo            = $defenderActivo
            defender_actualizado       = $defenderActualizado
            firewall_activo            = $firewallActivo
            actualizaciones_pendientes = $actualizacionesPendientes
            actualizaciones_criticas   = $actualizacionesCriticas
            lista_actualizaciones      = $listaActualizaciones
            usuarios_admin             = $usuariosAdmin
            puertos_escucha            = $puertos
            procesos_sospechosos       = $sospechosos
            todos_procesos             = $todosProcesos
            eventos_seguridad          = $eventos
            software_instalado         = $software
        }
        rendimiento = [PSCustomObject]@{
            cpu_porcentaje = $cpu
            ram_porcentaje = $ramUsada
        }
        puntuacion_seguridad = $puntuacion
    }
    return $datos
}

function Enviar-Datos($datos) {
    try {
        $json     = $datos | ConvertTo-Json -Depth 10 -Compress
        $headers  = @{"X-API-Key" = $API_KEY}
        $response = Invoke-RestMethod -Uri $WEBHOOK_URL -Method POST -Body $json -ContentType "application/json; charset=utf-8" -Headers $headers
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Datos enviados - Puntuacion: $($datos.puntuacion_seguridad)/100"
        return $true
    } catch {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Error: $_"
        return $false
    }
}

function Ejecutar-Comandos {
    try {
        $headers  = @{ "X-API-Key" = $API_KEY }
        $hostname = $env:COMPUTERNAME
        $resp     = Invoke-RestMethod -Uri "http://91.98.126.215:8000/agente/comandos/$hostname" -Headers $headers -Method GET -ErrorAction Stop
        
        foreach ($cmd in $resp.comandos) {
            $resultado = ""
            $exito     = $false
            try {
                switch ($cmd.tipo) {
                    "matar_proceso" {
                        Stop-Process -Id $cmd.params.pid -Force -ErrorAction Stop
                        $resultado = "Proceso PID $($cmd.params.pid) terminado correctamente"
                        $exito     = $true
                    }
                    "bloquear_ip" {
                        $ip = $cmd.params.ip
                        New-NetFirewallRule -DisplayName "Noctua-Block-$ip" -Direction Inbound -RemoteAddress $ip -Action Block | Out-Null
                        New-NetFirewallRule -DisplayName "Noctua-Block-$ip-Out" -Direction Outbound -RemoteAddress $ip -Action Block | Out-Null
                        $resultado = "IP $ip bloqueada en firewall Windows"
                        $exito     = $true
                    }
                    "snapshot_inmediato" {
                        $resultado = "Snapshot inmediato completado en este ciclo"
                        $exito     = $true
                    }
                    default {
                        $resultado = "Comando desconocido: $($cmd.tipo)"
                    }
                }
            } catch {
                $resultado = "Error ejecutando comando: $_"
            }

            # Reportar resultado al servidor
            $body = @{ resultado = $resultado; exito = $exito } | ConvertTo-Json
            Invoke-RestMethod -Uri "http://91.98.126.215:8000/agente/comando/$hostname/$($cmd.id)/resultado" `
                -Headers $headers -Method POST -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Cmd: $($cmd.tipo) -> $resultado"
        }
    } catch {
        # Sin comandos pendientes o sin conexion — continuar normalmente
    }
}

# ── Bucle principal ───────────────────────────────────────────────────────────
Write-Host "ASOAR Agent v1.0 - $env:COMPUTERNAME"
Write-Host "Webhook: $WEBHOOK_URL"

while ($true) {
    $datos = Obtener-DatosSeguridad
    Enviar-Datos $datos
    Ejecutar-Comandos
    Start-Sleep -Seconds $INTERVALO_SEGUNDOS
}
