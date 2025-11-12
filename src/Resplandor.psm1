# ============================== Resplandor.ps1 ==============================
# 1) Eventos (CSV/HTML/XML)  2) Procesos+Red (CSV/HTML)  3) AbuseIPDB (CSV/HTML)  4) RAM opcional (WinPmem)
# Probado en Windows PowerShell 5.1. ASCII-safe.
# NOTA: No se usa Set-StrictMode.

param(
    [switch]$Auto,
    [datetime]$Desde = (Get-Date).AddDays(-7),
    [string]$ClaveAbuse,
    [string]$SalidaBase,
    [switch]$CapturarRAM
)

# Asignar parámetros a variables de script para disponibilidad global
$script:Auto = $Auto
$script:Desde = $Desde
$script:ClaveAbuse = $ClaveAbuse
$script:SalidaBase = $SalidaBase
$script:CapturarRAM = $CapturarRAM

$ErrorActionPreference = "SilentlyContinue"

# ------------------------------------ Helpers ------------------------------------
function New-RFOutputRoot {
    [CmdletBinding()]
    param([string]$RootDir)

    $base = ""; $dir = ""
    if ($RootDir -and (Test-Path $RootDir)) {
        $leaf = Split-Path $RootDir -Leaf
        if ($leaf -like 'Resplandor_*') { $dir = $RootDir } else { $base = $RootDir }
    } elseif ($RootDir -and -not (Test-Path $RootDir)) {
        $base = $RootDir
        New-Item -ItemType Directory -Path $base -Force | Out-Null
    } else {
        if (Test-Path "$env:USERPROFILE\OneDrive\Desktop") { $base = "$env:USERPROFILE\OneDrive\Desktop" }
        else                                               { $base = "$env:USERPROFILE\Desktop" }
    }
    if (-not $dir) {
        if (-not (Test-Path $base)) { New-Item -ItemType Directory -Path $base -Force | Out-Null }
        $name = "Resplandor_{0}" -f (Get-Date -Format "yyyyMMdd_HHmmss")
        $dir  = Join-Path $base $name
    }
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    foreach ($s in @('eventos','procesos','reputacion')) {
        $sub = Join-Path $dir $s
        if (-not (Test-Path $sub)) { New-Item -ItemType Directory -Path $sub -Force | Out-Null }
    }
    return $dir
}

function Test-RFPrivateIP {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Ip)
    try { $addr = [System.Net.IPAddress]::Parse($Ip) } catch { return $false }
    $b = $addr.GetAddressBytes(); if ($b.Length -ne 4) { return $false }
    switch ($b[0]) {
        10  { return $true }
        172 { if ($b[1] -ge 16 -and $b[1] -le 31) { return $true } else { return $false } }
        192 { if ($b[1] -eq 168) { return $true } else { return $false } }
        default { return $false }
    }
}

# --------------------------------- Tarea 1: Eventos ---------------------------------
function Get-RFEventEvidence {
    [CmdletBinding()]
    param(
        [datetime]$Desde = (Get-Date).AddDays(-7),
        [string[]]$Logs = @('Security','System','Application'),
        [int[]]$EventIds,
        [string]$OutputDir,
        [ValidateSet('CSV','HTML','XML')][string[]]$Formats = @('CSV','HTML'),
        [switch]$OnlySuspicious
    )

    $outRoot = New-RFOutputRoot -RootDir $OutputDir
    $outDir  = Join-Path $outRoot 'eventos'
    $suspect = @(4624,4625,4672,4688,1102,7045,4720,4728,4732,4738)

    $paths=@{}; $countBy=@{}

    foreach ($log in $Logs) {
        $fh = @{ LogName = $log; StartTime = $Desde }
        if     ($OnlySuspicious) { $fh['Id'] = $suspect }
        elseif ($EventIds)       { $fh['Id'] = $EventIds }

        $events = @()
        try { $events = @(Get-WinEvent -FilterHashtable $fh -ErrorAction Stop) } catch { $events = @() }

        $countBy[$log] = @($events).Count

        if ('CSV' -in $Formats) {
            $csv = Join-Path $outDir ("{0}_{1}.csv" -f $log,(Get-Date -Format 'yyyyMMdd_HHmmss'))
            $events | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,
                @{n='Message';e={ [string]$_.Message }} | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csv
            $paths["$log:CSV"] = $csv
        }
        if ('HTML' -in $Formats) {
            $html = Join-Path $outDir ("{0}_{1}.html" -f $log,(Get-Date -Format 'yyyyMMdd_HHmmss'))
            $events | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,
                @{n='Extract';e={ ([string]$_.Message).Substring(0,[Math]::Min(200,([string]$_.Message).Length)) }} |
                ConvertTo-Html -Title ("Eventos {0}" -f $log) | Out-File -Encoding UTF8 $html
            $paths["$log:HTML"] = $html
        }
        if ('XML' -in $Formats) {
            $xml = Join-Path $outDir ("{0}_{1}.xml" -f $log,(Get-Date -Format 'yyyyMMdd_HHmmss'))
            $xmlLines = @(); foreach ($e in $events) { $xmlLines += $e.ToXml() }
            Set-Content -Path $xml -Value $xmlLines -Encoding UTF8
            $paths["$log:XML"] = $xml
        }
    }

    [pscustomobject]@{
        OutputFolder = $outRoot
        CountByLog   = $countBy
        Paths        = $paths
    }
}

# ---------------------- Tarea 2: Procesos + conexiones de red ----------------------
function Get-RFProcessNetworkMap {
    [CmdletBinding()]
    param([string]$OutputDir)

    $outRoot = New-RFOutputRoot -RootDir $OutputDir
    $outDir  = Join-Path $outRoot 'procesos'

    $net  = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -in @('Established','Listen') })
    $proc = @(Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath,CommandLine)

    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($n in $net) {
        $p = $null; foreach ($pp in $proc) { if ($pp.ProcessId -eq $n.OwningProcess) { $p = $pp; break } }

        $ruta = if ($p -and $p.ExecutablePath) { $p.ExecutablePath } else { $null }

        $sigStatus = $null
        if ($ruta -and (Test-Path $ruta)) {
            try { $sigStatus = (Get-AuthenticodeSignature -LiteralPath $ruta).Status } catch { $sigStatus = 'UnknownError' }
        } else { $sigStatus = 'PathMissing' }

        $flags = @(); if ($sigStatus -ne 'Valid') { $flags += 'sin_firma' }

        $rl = if ($ruta) { $ruta.ToLower() } else { '' }
        if ($rl -like 'c:\users\*\appdata\local\temp*') { $flags += 'en_temp' }
        if ($rl -like 'c:\users\public*')               { $flags += 'en_public' }
        if ($rl -like 'c:\users\*\downloads*')          { $flags += 'en_downloads' }

        $rem = ""
        if ($n.RemoteAddress) {
            $rem = ("{0}:{1}" -f $n.RemoteAddress,$n.RemotePort)
            if (-not (Test-RFPrivateIP $n.RemoteAddress)) { $flags += 'ip_publica' }
        }

        $procName = '<desconocido>'; if ($p -and $p.Name) { $procName = $p.Name }

        $row = [pscustomobject]@{
            PID        = $n.OwningProcess
            Proceso    = $procName
            Ruta       = $ruta
            Cmd        = if ($p) { $p.CommandLine } else { $null }
            Local      = ("{0}:{1}" -f $n.LocalAddress,$n.LocalPort)
            Remoto     = $rem
            Estado     = $n.State
            Sospechoso = [bool]((@($flags)).Count -ge 2)
            Razones    = ($flags -join ',')
        }
        [void]$rows.Add($row)
    }

    $csv = Join-Path $outDir ("procesos_red_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csv

    $html = Join-Path $outDir ("procesos_red_{0}.html" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $rows | ConvertTo-Html -Title "Procesos y Red" | Out-File -Encoding UTF8 $html

    [pscustomobject]@{
        OutputFolder = $outRoot
        CsvPath      = $csv
        HtmlPath     = $html
        Table        = $rows
    }
}

# ------------------------ Tarea 3: Reputacion IP (AbuseIPDB) -----------------------
function Invoke-RFAbuseIpLookup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ApiKey,
        [string[]]$IpList,
        [int]$MaxAgeDays = 365,
        [string]$OutputDir
    )

    $outRoot = New-RFOutputRoot -RootDir $OutputDir
    $outDir  = Join-Path $outRoot 'reputacion'

    $headers = @{ Key = $ApiKey; Accept = 'application/json' }
    $rows = New-Object System.Collections.Generic.List[object]

    $ips = @()
    if ($IpList) { $ips = $IpList | Where-Object { $_ -and ($_ -ne '0.0.0.0') } | Sort-Object -Unique }

    foreach ($ip in $ips) {
        if (Test-RFPrivateIP $ip) { continue }
        $u = "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=$MaxAgeDays&verbose"
        try {
            $r = Invoke-RestMethod -Method GET -Uri $u -Headers $headers -ErrorAction Stop
            $score = $r.data.abuseConfidenceScore
            if     ($score -ge 75) { $nivel = 'alto' }
            elseif ($score -ge 40) { $nivel = 'medio' }
            elseif ($score -ge 10) { $nivel = 'bajo' }
            else                   { $nivel = 'minimo' }
            $row = [pscustomobject]@{
                IP     = $ip
                Score  = $score
                Nivel  = $nivel
                Total  = $r.data.totalReports
                ISP    = $r.data.isp
                Pais   = $r.data.countryCode
                Hosts  = ($r.data.hostnames -join ',')
            }
            [void]$rows.Add($row)
        } catch {
            $row = [pscustomobject]@{
                IP    = $ip
                Score = $null
                Nivel = 'error_api'
                Total = $null
                ISP   = $null
                Pais  = $null
                Hosts = $null
            }
            [void]$rows.Add($row)
        }
        Start-Sleep -Milliseconds 700
    }

    $csv = Join-Path $outDir ("abuseip_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csv

    $html = Join-Path $outDir ("abuseip_{0}.html" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $rows | ConvertTo-Html -Title "Reputacion IP (AbuseIPDB)" | Out-File -Encoding UTF8 $html

    [pscustomobject]@{
        OutputFolder = $outRoot
        CsvPath      = $csv
        HtmlPath     = $html
        Table        = $rows
    }
}

# --------------------------- (Opcional) Captura de RAM ---------------------------
function Invoke-RFRamCapture {
    [CmdletBinding()]
    param([string]$ToolPath = "C:\Herramientas\winpmem.exe")

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-Host "[WARN] Se requieren privilegios de administrador para capturar RAM." -ForegroundColor Yellow
        return $false
    }
    if (-not (Test-Path $ToolPath)) {
        Write-Host "[WARN] No se encontro winpmem en: $ToolPath" -ForegroundColor Yellow
        Write-Host "       Descargalo desde https://github.com/Velocidex/WinPmem y colocalo ahi."
        return $false
    }
    $forDir = "C:\Forensics"
    if (-not (Test-Path $forDir)) { New-Item -ItemType Directory -Path $forDir -Force | Out-Null }
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $outRaw = Join-Path $forDir ("RAM_Capture_{0}.raw" -f $ts)

    Write-Host "[INFO] Capturando RAM con WinPmem... puede tardar" -ForegroundColor Cyan
    & $ToolPath -o $outRaw -d

    if (Test-Path $outRaw) {
        $h = Get-FileHash -Path $outRaw -Algorithm SHA256
        $h | Export-Clixml -Path ($outRaw + ".sha256")
        Write-Host ("[OK] RAM capturada: {0}" -f $outRaw) -ForegroundColor Green
        Write-Host ("[OK] SHA256: {0}" -f $h.Hash) -ForegroundColor Green
        return $true
    } else {
        Write-Host "[WARN] No se genero el archivo de captura." -ForegroundColor Yellow
        return $false
    }
}

# --------------------------- Orquestacion (full run) ---------------------------
function Invoke-RFFullRun {
    [CmdletBinding()]
    param([datetime]$Desde = (Get-Date).AddDays(-7), [string]$AbuseApiKey, [string]$OutputDir)

    $root = New-RFOutputRoot -RootDir $OutputDir

    $ev   = Get-RFEventEvidence -Desde $Desde -OutputDir $root -Formats @('CSV','HTML') -OnlySuspicious
    $pr   = Get-RFProcessNetworkMap -OutputDir $root

    $ips = @()
    foreach ($t in $pr.Table) {
        if ($t.Remoto) {
            $ip = ($t.Remoto -split ':')[0]
            if ($ip) { $ips += $ip }
        }
    }
    $ips = $ips | Sort-Object -Unique

    $rep = $null
    if ($AbuseApiKey) { $rep = Invoke-RFAbuseIpLookup -ApiKey $AbuseApiKey -IpList $ips -OutputDir $root }

    $sum = Join-Path $root 'Resumen_Forense.txt'
    "Resplandor - Equipo: $env:COMPUTERNAME"                         | Out-File -Encoding UTF8 $sum
    "Fecha: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"               | Out-File -Append -Encoding UTF8 $sum
    "Desde: $Desde"                                                  | Out-File -Append -Encoding UTF8 $sum
    ""                                                               | Out-File -Append -Encoding UTF8 $sum
    "== Eventos (sospechosos) =="                                    | Out-File -Append -Encoding UTF8 $sum
    foreach ($kv in ($ev.CountByLog.GetEnumerator() | Sort-Object Name)) {
        ("{0}: {1}" -f $kv.Key,$kv.Value) | Out-File -Append -Encoding UTF8 $sum
    }
    ""                                                               | Out-File -Append -Encoding UTF8 $sum
    "== Procesos/Red =="                                             | Out-File -Append -Encoding UTF8 $sum
    ("Total filas: {0}" -f (@($pr.Table)).Count)                     | Out-File -Append -Encoding UTF8 $sum
    ("Sospechosos: {0}" -f ((@($pr.Table) | Where-Object { $_.Sospechoso })).Count) | Out-File -Append -Encoding UTF8 $sum
    ""                                                               | Out-File -Append -Encoding UTF8 $sum
    if ($rep) {
        "== Reputacion IP (AbuseIPDB) =="                            | Out-File -Append -Encoding UTF8 $sum
        ("Consultadas: {0}" -f (@($rep.Table)).Count)                | Out-File -Append -Encoding UTF8 $sum
        foreach ($g in ($rep.Table | Group-Object Nivel)) {
            ("{0}: {1}" -f $g.Name,$g.Count) | Out-File -Append -Encoding UTF8 $sum
        }
    } else {
        "== Reputacion IP (AbuseIPDB) omitida: sin clave =="         | Out-File -Append -Encoding UTF8 $sum
    }
    ""                                                               | Out-File -Append -Encoding UTF8 $sum
    "Salidas:"                                                       | Out-File -Append -Encoding UTF8 $sum
    ("  Eventos:   {0}" -f (Join-Path $root 'eventos'))              | Out-File -Append -Encoding UTF8 $sum
    ("  Procesos:  {0}" -f (Join-Path $root 'procesos'))             | Out-File -Append -Encoding UTF8 $sum
    ("  Reputacion:{0}" -f (Join-Path $root 'reputacion'))           | Out-File -Append -Encoding UTF8 $sum

    [pscustomobject]@{
        OutputFolder = $root
        Eventos      = $ev
        ProcNet      = $pr
        Reputacion   = $rep
        ResumenPath  = $sum
    }
}

# --------------------------------- UI ---------------------------------
function Show-Menu {
@"
++::::.+++-+..::+--::.::::::.::::::::::::-------:::::::+:++++------------++:+-------+++:++++++++++++++++++++-+-----++-------+----++++++---+++++++:::::
::::::...:::..::+--::....::::::.:::::+++--------+++++-+::++++------------++++-------++++++++++:+++++++-+----+---*******-----++---++++++:-*-+++++::::::
::::::::::::.:::::::::::::::.:::::::+++++-------+------+:::++----------+:::++-------++++++++++++++++-+-+++-----**-++++----------------+:-*-----++++:::
:::+::::::::::::+++---+::::::.:::::+++++++--------------+::++------:::::::::::++----++++++++++++++++-+++-**++-*-:--+-----++---**-:-****+-*-::*-::*-::+
----+:::::::::::::+---+:::::..::::::-------------------:::+++---::::::::::::::+++---++++++++++++++++-+++-#*:+-**+----------******---+-+:-*-::+*:*--:++
-----:+:::::--++++:+---+:::::::::::::+----------+---+-+:+:++++:::::::++::+--++++++++++++++++++++++++++++-*-+++-**-----------++-**-----+:-*--::-**--:++
---+:::::::-++--:::::+++-+++:::++:+---+-------+-++::+-----+++:::+------------++:::+++++:+++++++++:++++++*#*-+++--******-+-*******-----+::+--+:-*-++::+
+::::::::::++--+:::::::+---+::::::::+--+:+-+++:+:::+-------+::+--**********---:::+++::::::::+++::::+::+:++++++++++++++-+++++++++-----++:++++:-*-:::::+
++:::::::::++::::::::::+---+:.::::::+:::::::::::-+:++++::::++:--*************--:::++::::::::::::::::::+++--+++++:::::::::::::::::::::::::::+:--:::::::
::::::::::::+::::::::::::--+::::::::::::::+::+++++++++++:::::+--**************--::+++--------++++++---++++::::::::::::::::::::::::::::::::::::::::::::
::::::::::::+::::::::::+---+:::+::::::::::-++++++++++-++:++:::----*************--:+++---------------*-++-------+++++++:::::+::::+---+++++++++++--+-:::
-+::::::::::+::::::::::::::.::::::::::::::::::+++++:++++++--++----*******--*****---++--------------------+++++++++++++::+++++++++-----++++++:::-+++:::
--::::::::::::::::+::::::::::::::::::::::::+:::+++++++++++++--******************---++-----------------+++::::::::::::::::::::::::::++++---------++-:::
::::::::::::::::+---+:::::::::::++::++++++++++++-+:++++++++---*****************----++-----------------+++:::++:::++::+:++:+::::+++++:::+---++++++:::::
::::+++-+:::::::+---+:::::::::.::::::::::::+::::::::::+-:::+---****************----++----------------++-+::::+:::::::::++::::+-+:::+:::+--+++++++++:::
::::::+++::::::::+-+:::::::::::::+++++++:+++++++++++-+--+++----***--***********-+--++--------------+-++-+::::+:+:::::::++::::++::::::::++++++-+++++:::
:::::::::::::::::::::::::::::::::::::++:::::::+++++:::+++:+++----*************-++-+:+--------:::---:-++++:::++:::+::::++:::::++:::+::::++++++-++++::::
:::::::::::::::::::::::::::::.:::++++--+++:::::++:++++++:+-++------**********-++++:::+---------------++++::::::::::::::::::::::+++:::::++++++++++-+::.
:::::::::::::..........::::::::::::::::+++-++++++---------------+-+--*******--++::::+--+:---+::-:::::++--++++++::::++::+:::::::::::::::-+::::::+:::::.
::...:::::::::::::::::::::::::::+::::::::+-+::::+::++++---------+++--*******-+++:::+--------+:+-+::::::-++::+++++::::++:::+:::::+++++++++-------++:::.
:::::::::::::::::::::::::::::::::::::-++++++++++----------------:+--*******--++::::----------++-++++----------------------+::::+++++++++++++++++++::::
+::::::::::::::::::::::::::::::::::::++::::::+++-++++-----------+---****---+++:::::-----***---+-++++++---------------------+++++--++--------------::::
::::::::::::::::::::::::::::::::::::++:+:++++++-----------+++---+---***----++:::::----*******---++++-***--***-------------+---+----------+------------
:::::::::::::::::::::::::::::::+::::+::::+::+++-++++------+++-------------++:::::+----*****-----++++*****-****----+-------++--+++++------+------------
::::::::::::::::::::::------::::::::+++------++-++++------+++-------------+--+::+-----**-***----++++**-**-****----+------++-----+-------++------------
::::::::::::::::::::+------------++::::+::-+:+++++-------++++-------*---***--++++-----**-****---::::-********-----+------++--------------++-----------
::::::::::::::::::::-------------------+----+:::::+-------+-++--------*****--+++---------------------+-****-----------------------------+++-----------
:::::::::::::::::::--------*---------------+++++-+-------++-----------*****---+---------------------------------------------------------++------------
::::::::::::::::-----------------------------------------++----------*****--------------------------------------------------------------+------------+
:::::::::::::::+--+-------------:::-----------------------+---------*******-++++----**----------------------+++++-------++++-----------+-+------------
:::::::::::::::::+----------+:.::++-+:+------------------:+---------*******---++----**-----------:+-------------------------------------------------+:
::::::::::::::::::------+---+:::::::::::::--------------:+++-------********-------*****----------:++++++++++++::+++-----------------------------------
:::::::::::::::::::+-::::--+++::++++++::+::::+--------+:------***--********------******-----------+++++++++++++++++++++++++++::++---------------------
::::::::::::::::::::++::::++::::::::+--+:+---+++::::::::::+-+-****-*********-**********-----------+::++++++++++++++++++++++++++++++++++++++++:++++----
---::::::::::::::::::::+:::--::::++++--+::-::::::::::+-++++---****-*********************----------:+++++:::+----++++++++++++++++++++++++++++++++++++++
-*--:::::::::+-++::::+++::::-+:::::+++:::+-++:::+:::::+::::----***-********************-----------:++++++++++++++++++-++++++++++++++:++++++++++++++++:
-*--::::::::::::::::::::::::::::::::::::::::+:::-::::+----+--*************************------------++:::::::+::++++++++++++++++++++++:+++++++++++++++:+
-----::::::::::::::::::::::::::::::::::+::++++++-:::::::::+-**************************--:+---------+++++::::++++:::++++++++++++++++::+++++++++++++++++
-----::::::++::::+++:::+:::::::::+::++::.::++++:+----+++++-**-**************************-----------+++++++:++++++++:+++++++++++:::+:::++++++++++++::+:
-*---:::+++++:::+-------+---+--++::::::::++++++++-+::++++--****************************------------::++++:::+++++++++++++++++++++++++:::::::::::::::::
-*---+:::::::::::::::+::::+++::+::::::::::::+:++-----+-++---****************************----------::+++++:::+++++++++++++++++++++++:::::::::::::::::::
-*----::::::::::::::::+++++++:::::::::+::+++-+::::++++-++-----*********************----*****----:::++-+++:::+++++++++++++++++++++++:::::::::::::::::::
------+::::::::::::++:+++-++:::::::::::::::+::++--+++--+-----*********************----*******-:::+++++:::++-+++---+++++++++++++++++:::::::::::::::::::
-------::::+:::::::::+----+++:::::::::::::++++++-+:+++++----**********************-***********::++++++++++:++++++++++++---++++++++++::::::::::::::::::
-------:::::::++::::::+--++++:::::::::::::::-+++----++++----*******************************-**+:::::+:++::::++:+++++++-***-++++++++:::::::::::::::::::
--**---:::::::::::::++:+++:+++::::::::::-----::::::++++-----******##%%@@%**%@@%%%%%#******--**-:::+::::::::+::::::++++-***-:+++++++:::::::::::::::::::
---*---+:::::::::::::+++:::++++:::::::++-------------++--**##*%#*#******-------**@@@%@@%%#***-+::::::::::::::::::::::+-***-::++++++:::::::::::::::::::
-------+::::::::::::::+-++++++++++::++:++-------------***##********---------------******#**##*++:::::::::::::::::::::+-***-::+++++::::::::::::::::::::
-------+::::::::::::::++++++::::::++++++-------------*****-------*****----***********----******-+::::::::::::::::::::-****-:::++++::::::::::::::::::::
*-------:::::::::::::::+++:::::::::::++--------------****------**-*-******----********------***-:::::::::::::::::::::--***-::+++++::::::::::::::::::::
********+::+++---+--------------+:::+++--------------***------*---*********--**********-----***::::::::::::::::::++::+-***-::+++::::::::::::::::::::::
*******----++++++------------****---*---+-------------**#**-----*--*****-***********-*--***#**---+:+--++:::::::::::::+-***-::+++:+::::::::::::::::::::
*****-***-----++++------------*-----------------------*****#%%%%%#*****--**********#%%%%%****-------------++---++::::+-***-::++++:::::::::::::::::::::
*******-*-++++----------------------------------***********##%%%%%%%%%@@@@@@@@%%%%%##%###***------------------------++-***-:::::+:::::::::::::::::::::
********+:++++++++++--------**-----------------*************###%%%%%%%%@@@@%%%%%%%%%%%##****-------------*------------****---+++::::::::::::::::::::::
**--**::++++++++++---------------------------****************###%%%%%%%%%%%%%%%%%%%%%#****-------+----------------*---*#*******#@%*-*-******---*****-*
**-::++++---++-----------------*----------********-*************##%%%%%%%%%%%%%%%%###***--------------+-----------**-**#**-***%*#@*---*****-**-***-***
::+++++-----------------------*********---**************************############*****-------------+----:-------*------*#****#@@*#@@@@#@@@@%******--***
++++----------------------********************************************************-----------------:----:---*---------*#***#%%%**%%%*******#**-*-*#%#*
----------------------********************####***#*******************************-------------------:----+-*---------*##**********************-***%%#*
-------------------**********************##################**********************--*-----------------+--+----**---**#*##**#******#%%%####%%***********
---*******************###*####**######%###%%##%%#%%%%%%%%%%%%%%%%%#*********************************---*--*********%%%%%*****%@#****#**###%%%%********


_____________________ ___________________.____       _____    _______  ________   ________ __________ 
\______   \_   _____//   _____/\______   \    |     /  _  \   \      \ \______ \  \_____  \\______   \
 |       _/|    __)_ \_____  \  |     ___/    |    /  /_\  \  /   |   \ |    |  \  /   |   \|       _/
 |    |   \|        \/        \ |    |   |    |___/    |    \/    |    \|    `   \/    |    \    |   \
 |____|_  /_______  /_______  / |____|   |_______ \____|__  /\____|__  /_______  /\_______  /____|_  /
        \/        \/        \/                   \/       \/         \/        \/         \/       \/ 
1) Ejecucion completa (eventos + procesos/red + AbuseIPDB)
2) Solo eventos
3) Solo procesos + red
4) Solo reputacion de IPs (AbuseIPDB)
5) Abrir ultima carpeta Resplandor_*
6) Capturar RAM ahora (WinPmem)
7) Salir
===========================================================
"@
}

function Get-LastOutputFolder {
    $roots = @()
    if (Test-Path "$env:USERPROFILE\OneDrive\Desktop") { $roots += "$env:USERPROFILE\OneDrive\Desktop" }
    if (Test-Path "$env:USERPROFILE\Desktop")          { $roots += "$env:USERPROFILE\Desktop" }
    $dirs = @()
    foreach ($r in $roots) {
        $items = @(Get-ChildItem -Path $r -Directory -Filter 'Resplandor_*' -ErrorAction SilentlyContinue)
        if ($items) { $dirs += $items }
    }
    $dirs = $dirs | Sort-Object LastWriteTime -Descending
    if ($dirs -and $dirs.Count -gt 0) { return $dirs[0].FullName } else { return $null }
}

# --------------------------------- Flujo principal ---------------------------------
if ($script:Auto) {
    $res = Invoke-RFFullRun -Desde $script:Desde -AbuseApiKey $script:ClaveAbuse -OutputDir $script:SalidaBase
    if ($script:CapturarRAM) { Invoke-RFRamCapture | Out-Null }
    Write-Host ("[OK] Listo (modo -Auto). Carpeta: {0}" -f $res.OutputFolder)
    exit
}

# Modo interactivo:
while ($true) {
    Clear-Host
    Show-Menu
    $opt = Read-Host 'Selecciona una opcion'
    switch ($opt) {
        '1' {
            if (-not $script:ClaveAbuse) {
                $script:ClaveAbuse = Read-Host 'Clave AbuseIPDB (Enter para omitir reputacion)'
                if (-not $script:ClaveAbuse) { Write-Host "[INFO] Reputacion se omitira (sin clave)." -ForegroundColor Yellow }
            }
            $r = Invoke-RFFullRun -Desde $script:Desde -AbuseApiKey $script:ClaveAbuse -OutputDir $script:SalidaBase
            Write-Host ("[OK] Salida: {0}" -f $r.OutputFolder)
            $q = Read-Host "Capturar RAM al finalizar? (s/n)"
            if ($q -match '^[sS]$') { Invoke-RFRamCapture | Out-Null }
            Read-Host 'Enter para continuar' | Out-Null
        }
        '2' {
            $ev = Get-RFEventEvidence -Desde $script:Desde -OutputDir $script:SalidaBase -Formats CSV,HTML -OnlySuspicious
            Write-Host ("[OK] Eventos -> {0}" -f $ev.OutputFolder)
            Read-Host 'Enter para continuar' | Out-Null
        }
        '3' {
            $pr = Get-RFProcessNetworkMap -OutputDir $script:SalidaBase
            Write-Host ("[OK] Procesos/Red -> {0}" -f $pr.OutputFolder)
            Read-Host 'Enter para continuar' | Out-Null
        }
        '4' {
            if (-not $script:ClaveAbuse) {
                $script:ClaveAbuse = Read-Host 'Clave AbuseIPDB (requerida para reputacion)'
            }
            if ($script:ClaveAbuse) {
                $last = Get-LastOutputFolder
                $ips  = @()
                if ($last -and (Test-Path (Join-Path $last 'procesos'))) {
                    $latestCsv = $null
                    $cands = @(Get-ChildItem (Join-Path $last 'procesos') -Filter 'procesos_red_*.csv' -ErrorAction SilentlyContinue |
                              Sort-Object LastWriteTime -Desc | Select-Object -First 1)
                    if ($cands -and $cands.Count -gt 0) { $latestCsv = $cands[0] }
                    if ($latestCsv) {
                        $tbl = Import-Csv $latestCsv.FullName
                        foreach ($row in $tbl) {
                            if ($row.Remoto) { $ip = ($row.Remoto -split ':')[0]; if ($ip) { $ips += $ip } }
                        }
                        $ips = $ips | Sort-Object -Unique
                    }
                }
                if (-not $ips -or $ips.Count -eq 0) {
                    Write-Host 'No hay IPs previas; ingresa una lista (coma separada):'
                    $raw = Read-Host 'IPs'
                    if ($raw) {
                        $ips = @()
                        foreach ($part in ($raw -split ',')) { $trim = $part.Trim(); if ($trim) { $ips += $trim } }
                    }
                }
                if ($ips -and $ips.Count -gt 0) {
                    $rep = Invoke-RFAbuseIpLookup -ApiKey $script:ClaveAbuse -IpList $ips -OutputDir $script:SalidaBase
                    Write-Host ("[OK] Reputacion -> {0}" -f $rep.OutputFolder)
                } else {
                    Write-Host "[INFO] No se encontraron IPs para consultar." -ForegroundColor Yellow
                }
            } else {
                Write-Host "[WARN] Sin clave de AbuseIPDB, no se puede consultar reputacion." -ForegroundColor Yellow
            }
            Read-Host 'Enter para continuar' | Out-Null
        }
        '5' {
            $last = Get-LastOutputFolder
            if ($last) { Write-Host $last; ii $last } else { Write-Host '[INFO] No se encontro carpeta Resplandor_*' }
            Read-Host 'Enter para continuar' | Out-Null
        }
        '6' {
            Invoke-RFRamCapture | Out-Null
            Read-Host 'Enter para continuar' | Out-Null
        }
        '7' { break }
        default { Write-Host '[INFO] Opcion invalida'; Start-Sleep 1 }
    }
}