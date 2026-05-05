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

    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $updates = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
        $actualizacionesPendientes = $updates.Updates.Count
        $actualizacionesCriticas = ($updates.Updates | Where-Object { $_.MsrcSeverity -eq "Critical" }).Count
    } catch {
        $actualizacionesPendientes = -1
        $actualizacionesCriticas = -1
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

    # Procesos sospechosos
    try {
        $procesosSospechosos = @("mimikatz","meterpreter","netcat","nc","psexec","pwdump","wce","fgdump","gsecdump","procdump","cobaltstrike","beacon","empire","powersploit","nishang","metasploit")
        $procesosActivos = Get-Process | Select-Object Name, Id, CPU, WorkingSet
        $sospechosos = @($procesosActivos | Where-Object { $nombre = $_.Name.ToLower(); $procesosSospechosos | Where-Object { $nombre -like "*$_*" } } | ForEach-Object {
            @{ nombre = $_.Name; pid = $_.Id; cpu = [math]::Round($_.CPU, 2); memoria_mb = [math]::Round($_.WorkingSet / 1MB, 2) }
        })
        $todosProcesos = @($procesosActivos | Select-Object -First 20 | ForEach-Object {
            @{ nombre = $_.Name; pid = $_.Id; cpu = [math]::Round($_.CPU, 2); memoria_mb = [math]::Round($_.WorkingSet / 1MB, 2) }
        })
    } catch {
        $sospechosos = @()
        $todosProcesos = @()
    }

    # Eventos de seguridad
    try {
        $eventos = @(Get-EventLog -LogName Security -Newest 10 -ErrorAction SilentlyContinue | ForEach-Object {
            @{
                tiempo = $_.TimeGenerated.ToString("yyyy-MM-dd HH:mm:ss")
                id = $_.EventID
                mensaje = $_.Message.Substring(0, [Math]::Min(100, $_.Message.Length))
                tipo = switch ($_.EventID) {
                    4624 { "Login exitoso" }
                    4625 { "Login fallido" }
                    4634 { "Logout" }
                    4648 { "Login con credenciales explicitas" }
                    4720 { "Usuario creado" }
                    4726 { "Usuario eliminado" }
                    4732 { "Usuario añadido a grupo admin" }
                    4756 { "Miembro añadido a grupo" }
                    default { "Evento $($_.EventID)" }
                }
            }
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
                @{
                    nombre = $_.DisplayName
                    version = $_.DisplayVersion
                    publisher = $_.Publisher
                    fecha_instalacion = $_.InstallDate
                }
            })
    } catch {
        $software = @()
    }

    $puntuacion = 0
    if ($defenderActivo) { $puntuacion += 25 }
    if ($defenderActualizado) { $puntuacion += 20 }
    if ($firewallActivo) { $puntuacion += 25 }
    if ($actualizacionesCriticas -eq 0) { $puntuacion += 20 }
    if ($usuariosAdmin.Count -le 2) { $puntuacion += 10 }

    $datos = @{
        hostname = $hostname
        usuario = $usuario
        os = $os
        ip = $ip
        timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
        seguridad = @{
            defender_activo = $defenderActivo
            defender_actualizado = $defenderActualizado
            firewall_activo = $firewallActivo
            actualizaciones_pendientes = $actualizacionesPendientes
            actualizaciones_criticas = $actualizacionesCriticas
            usuarios_admin = $usuariosAdmin
            puertos_escucha = $puertos
            procesos_sospechosos = $sospechosos
            todos_procesos = $todosProcesos
            eventos_seguridad = $eventos
            software_instalado = $software
        }
        rendimiento = @{
            cpu_porcentaje = $cpu
            ram_porcentaje = $ramUsada
        }
        puntuacion_seguridad = $puntuacion
    }

    return $datos
}

function Enviar-Datos($datos) {
    try {
        $json = $datos | ConvertTo-Json -Depth 10
        $response = Invoke-RestMethod -Uri $WEBHOOK_URL -Method POST -Body $json -ContentType "application/json"
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
