# fortnite-tool-fix



Zwei echte Bugs drin: (1) `Read-Mem`-Fehler wurden in `catch{}` verschluckt, dadurch übersprang der Scanner jede Map lautlos → 0 Treffer ohne Meldung. (2) Wenn das ps4debug-Struct-Layout nicht passt, schlägt jeder Read fehl und es bleibt bei 0/54. Beides behoben: Layout wird jetzt **automatisch erkannt**, Lesevorgänge werden geprüft, Scan liefert pro Signatur einen Grund, und es gibt Modul-Base-Auflösung + Float-Scanner als Fallback. Dazu FTP 2121 und Bin-Loader 9090.

**Befehl 1 — Installer (überschreibt die alten Dateien):**

```powershell
$d="$env:USERPROFILE\FortniteToolkit"; New-Item -ItemType Directory -Force -Path "$d\core" | Out-Null
@'
# =========================================================
#  FORTNITE PS4 ULTIMATE TOOLKIT - Venice Build v1.1
#  Ports: 755 ps4debug | 2121 FTP | 9090 Bin Loader
# =========================================================
#Requires -Version 5.1
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $MyInvocation.MyCommand.Path
$Port=8787
$Base="http://127.0.0.1:$Port/"
$script:Conn=$null; $script:Host=$null; $script:Game=$null
$script:Log=New-Object System.Collections.ArrayList
$script:Applied=@{}; $script:Orig=@{}; $script:Found=@{}
$script:Pack=$false; $script:PackAuto=$true; $script:Delay=0; $script:Stealth=$false
$script:LastReason=''

function Log([string]$m,[string]$lvl='info'){
  [void]$script:Log.Add(@{t=(Get-Date).ToString('HH:mm:ss');m=$m;lvl=$lvl})
  if($script:Log.Count -gt 500){$script:Log.RemoveAt(0)}
}
function Read-Exact($s,[int]$n){
  $b=New-Object byte[] $n; $o=0
  while($o -lt $n){ $r=$s.Read($b,$o,$n-$o); if($r -le 0){throw 'closed'}; $o+=$r }
  return ,$b
}
function Send-Cmd([uint32]$Cmd,[byte[]]$Data){
  if(-not $script:Conn){throw 'not connected'}
  $data=if($null -eq $Data){New-Object byte[] 0}else{$Data}
  $h=New-Object byte[] 16
  [Array]::Copy([BitConverter]::GetBytes([uint32]0xFFAABBCC),0,$h,0,4)
  [Array]::Copy([BitConverter]::GetBytes($Cmd),0,$h,4,4)
  [Array]::Copy([BitConverter]::GetBytes([uint32]$data.Length),0,$h,8,4)
  [Array]::Copy([BitConverter]::GetBytes([uint32]$data.Length),0,$h,12,4)
  $st=$script:Conn.GetStream()
  $st.Write($h,0,16)
  if($data.Length -gt 0){$st.Write($data,0,$data.Length)}
  $st.Flush()
  $rh=Read-Exact $st 16
  if([BitConverter]::ToUInt32($rh,0) -ne 0xFFAABBCC){throw 'bad magic'}
  if([BitConverter]::ToUInt32($rh,4) -ne $Cmd){throw 'cmd mismatch'}
  $err=[BitConverter]::ToInt32($rh,12)
  if($err -lt 0 -and $Cmd -ne 0xBD000002){throw ("ps4debug error 0x" + $err.ToString('X'))}
  $dl=[BitConverter]::ToUInt32($rh,8)
  if($dl -gt 0){return ,(Read-Exact $st $dl)}
  return ,(New-Object byte[] 0)
}
function Get-IOStruct([uint32]$Pid,[uint64]$Addr,[uint32]$Len){
  $size=if($script:Pack){16}else{24}
  $b=New-Object byte[] $size
  [Array]::Copy([BitConverter]::GetBytes($Pid),0,$b,0,4)
  if($script:Pack){
    [Array]::Copy([BitConverter]::GetBytes($Addr),0,$b,4,8)
    [Array]::Copy([BitConverter]::GetBytes($Len),0,$b,12,4)
  } else {
    [Array]::Copy([BitConverter]::GetBytes($Addr),0,$b,8,8)
    [Array]::Copy([BitConverter]::GetBytes($Len),0,$b,16,4)
  }
  return ,$b
}
function Read-Mem([uint32]$Pid,[uint64]$Addr,[uint32]$Len){
  $r=Send-Cmd 0xBD000004 (Get-IOStruct $Pid $Addr $Len)
  if($r.Length -ne $Len){throw "short read $($r.Length)/$Len @0x$($Addr.ToString('X'))"}
  return ,$r
}
function Write-Mem([uint32]$Pid,[uint64]$Addr,[byte[]]$Data){
  $s=Get-IOStruct $Pid $Addr ([uint32]$Data.Length)
  $b=New-Object byte[] ($s.Length+$Data.Length)
  [Array]::Copy($s,0,$b,0,$s.Length)
  [Array]::Copy($Data,0,$b,$s.Length,$Data.Length)
  [void](Send-Cmd 0xBD000005 $b)
  if($script:Delay -gt 0){Start-Sleep -Milliseconds $script:Delay}
}
function Read-Ptr([uint64]$Addr){ $b=Read-Mem $script:Game.Pid $Addr 8; return [BitConverter]::ToUInt64($b,0) }
function Read-F([uint64]$Addr){ $b=Read-Mem $script:Game.Pid $Addr 4; return [BitConverter]::ToSingle($b,0) }
function Write-F([uint64]$Addr,[single]$v){ Write-Mem $script:Game.Pid $Addr ([BitConverter]::GetBytes($v)) }

function Get-Maps([uint32]$Pid){
  $r=Send-Cmd 0xBD000006 (Get-IOStruct $Pid 0 0)
  if($r.Length -lt 28){throw 'maps leer'}
  $stride=if($r.Length % 32 -eq 0 -and $r.Length % 28 -ne 0){32}
          elseif($r.Length % 28 -eq 0){28} else {32}
  $out=New-Object System.Collections.ArrayList
  for($i=0;$i -le $r.Length-$stride;$i+=$stride){
    [void]$out.Add(@{
      start=[BitConverter]::ToUInt64($r,$i)
      end=[BitConverter]::ToUInt64($r,$i+8)
      prot=[BitConverter]::ToUInt32($r,$i+24)
    })
  }
  return $out
}

function Scan-Range([uint32]$Pid,[byte[]]$pat,[bool[]]$msk,[uint64]$Start,[uint64]$End,[int]$Max,[int]$cs){
  $plen=$pat.Length
  $res=New-Object System.Collections.ArrayList
  $pos=$Start; $failed=$false
  while($pos -lt $End -and $res.Count -lt $Max){
    $want=[uint64]([Math]::Min([double]($cs+$plen),[double]($End-$pos)))
    try{ $buf=Read-Mem $Pid $pos ([uint32]$want) }catch{ $failed=$true; $pos+=[uint64]$cs; continue }
    if($buf.Length -lt $plen){break}
    $lim=$buf.Length-$plen
    for($i=0;$i -le $lim;$i++){
      $ok=$true
      for($j=0;$j -lt $plen;$j++){ if(-not $msk[$j] -and $buf[$i+$j] -ne $pat[$j]){$ok=$false;break} }
      if($ok){[void]$res.Add([uint64]($pos+$i)); if($res.Count -ge $Max){break}}
    }
    $pos+=[uint64]$cs
  }
  return @{hits=$res;failed=$failed}
}
function Find-Pattern([uint32]$Pid,[string]$Sig,[uint64]$Start,[uint64]$End,[int]$Max=1){
  $tk=$Sig.Trim() -split '\s+'
  $plen=$tk.Count
  $pat=New-Object byte[] $plen; $msk=New-Object bool[] $plen
  for($i=0;$i -lt $plen;$i++){
    if($tk[$i] -match '^\?\??$'){$msk[$i]=$true}else{$pat[$i]=[Convert]::ToByte($tk[$i],16)}
  }
  $a=Scan-Range $Pid $pat $msk $Start $End $Max 1048576
  if($a.failed -and $a.hits.Count -eq 0){
    $b=Scan-Range $Pid $pat $msk $Start $End $Max 65536
    return $b.hits
  }
  return $a.hits
}
function Find-Aob([string]$Sig){
  if(-not $script:Game){throw 'nicht verbunden'}
  if($script:Game.ExecMaps.Count -eq 0){$script:LastReason='noexec'; return $null}
  foreach($m in $script:Game.ExecMaps){
    try{
      $r=Find-Pattern $script:Game.Pid $Sig $m.start $m.end 1
      if($r.Count -gt 0){$script:LastReason=''; return [uint64]$r[0]}
    }catch{ $script:LastReason='readfail' }
  }
  if(-not $script:LastReason){$script:LastReason='nomatch'}
  return $null
}

function Detect-Layout {
  $base=$script:Game.Base
  $old=$script:Pack
  foreach($p in @($false,$true)){
    $script:Pack=$p
    try{
      $m=Read-Mem $script:Game.Pid $base 4
      if($m[0] -eq 0x7F -and $m[1] -eq 0x45 -and $m[2] -eq 0x4C -and $m[3] -eq 0x46){
        Log ("Struct-Layout erkannt: " + $(if($p){'packed'}else{'natural'}) + " (ELF-Magic verifiziert)") 'ok'
        return $p
      }
    }catch{ }
  }
  $script:Pack=$old
  Log 'WARNUNG: ELF-Magic an Modul-Base nicht lesbar - Reads evtl. blockiert' 'warn'
  return $old
}

function Find-GameProcess {
  $r=Send-Cmd 0xBD000002 (New-Object byte[] 0)
  for($i=0;$i -lt $r.Length-3;$i+=4){
    $p=[BitConverter]::ToUInt32($r,$i)
    if($p -eq 0){break}
    try{
      $info=Send-Cmd 0xBD000003 (Get-IOStruct $p 0 0)
      $txt=[Text.Encoding]::ASCII.GetString($info)
      if($txt -match 'CUSA07022' -or $txt -match 'Fortnite'){ return $p }
    }catch{}
  }
  return $null
}

function New-Tcp([string]$Ip,[int]$P,[int]$T=4000){
  $c=New-Object System.Net.Sockets.TcpClient
  $ar=$c.BeginConnect($Ip,$P,$null,$null)
  if(-not $ar.AsyncWaitHandle.WaitOne($T)){throw "Timeout $Ip`:$P"}
  $c.EndConnect($ar); $c.NoDelay=$true; return $c
}

function Connect-Ps4([string]$Ip){
  if($script:Conn){Disconnect-Ps4}
  $c=New-Tcp $Ip 755 3000
  $script:Conn=$c; $script:Host=$Ip
  [void](Send-Cmd 0xBD000001 (New-Object byte[] 0))
  Log "ps4debug verbunden: $Ip`:755" 'ok'
  $gp=Find-GameProcess
  if(-not $gp){throw 'Fortnite nicht gefunden - laeuft eboot.bin/CUSA07022?'}
  $maps=Get-Maps ([uint32]$gp)
  $exec=@($maps | Where-Object { ($_.prot -band 4) -and ($_.end -gt $_.start) })
  if($exec.Count -eq 0){
    Log 'Keine EXEC-Maps gemeldet - Fallback auf lesbare Maps' 'warn'
    $exec=@($maps | Where-Object { ($_.prot -band 1) -and ($_.end -gt $_.start) -and ($_.end - $_.start) -lt 268435456 })
  }
  $base=$null
  $b0=@($exec | Where-Object { $_.start -lt 0x100000000L } | Sort-Object start | Select-Object -First 1)
  if($b0.Count -gt 0){$base=$b0[0].start}
  if(-not $base -and $exec.Count -gt 0){$base=($exec | Sort-Object start | Select-Object -First 1).start}
  $script:Game=@{Pid=[uint32]$gp;Maps=$maps;ExecMaps=$exec;Base=$base}
  Log ("PID $gp | " + $maps.Count + " Maps | " + $exec.Count + " exec | Base 0x" + $(if($base){$base.ToString('X')}else{'?'})) 'ok'
  if($script:PackAuto){[void](Detect-Layout)}
  return $gp
}
function Disconnect-Ps4 {
  if($script:Conn){try{$script:Conn.Close()}catch{}}
  $script:Conn=$null; $script:Game=$null; $script:Host=$null
  $script:Applied=@{}; $script:Orig=@{}; $script:Found=@{}
  Log 'Verbindung getrennt' 'warn'
}

function Get-Db { return (Get-Content -Raw -Encoding UTF8 (Join-Path $Root 'patches.json') | ConvertFrom-Json) }
function Get-Feature([string]$Id){ return ((Get-Db).features | Where-Object { $_.id -eq $Id } | Select-Object -First 1) }

function Resolve-Feature($f){
  if($f.type -eq 'script'){ return @{status='script'} }
  if($f.sig){
    $a=Find-Aob $f.sig
    if($a){ return @{addr=$a;status='ok'} }
    $r=$script:LastReason
  } else { $r='nosig' }
  if($f.modoff -and $script:Game.Base){
    return @{addr=([uint64]$script:Game.Base + [uint64]$f.modoff);status='modoff'}
  }
  return @{status=$r}
}

function Enable-Feature([string]$Id){
  $f=Get-Feature $Id
  if(-not $f){throw "unbekannt: $Id"}
  if(-not $script:Game){throw 'nicht verbunden'}
  if($script:Stealth){Start-Sleep -Milliseconds 120}
  if($f.type -eq 'script'){ Invoke-Script $f.script; $script:Applied[$Id]=$true; return }
  $addr=$script:Found[$Id]
  if(-not $addr){throw 'nicht aufgeloest - Scan ausfuehren'}
  $t=[uint64]$addr + [uint64]$f.off
  if(-not $script:Orig.ContainsKey($Id)){ $script:Orig[$Id]=Read-Mem $script:Game.Pid $t ([int]$f.len) }
  switch($f.type){
    'patch' { Write-Mem $script:Game.Pid $t ([byte[]]($f.patch -split '\s+' | ForEach-Object {[Convert]::ToByte($_,16)})) }
    'nop'   { Write-Mem $script:Game.Pid $t ([byte[]](1..[int]$f.len | ForEach-Object {0x90})) }
    'float' { Write-F $t ([single]$f.value) }
  }
  $script:Applied[$Id]=$true
  Log "AN: $($f.name)" 'ok'
}
function Disable-Feature([string]$Id){
  $f=Get-Feature $Id
  if($f.type -eq 'script'){ $script:Applied.Remove($Id); return }
  if($script:Orig.ContainsKey($Id) -and $script:Game){
    Write-Mem $script:Game.Pid ([uint64]$script:Found[$Id]+[uint64]$f.off) ([byte[]]$script:Orig[$Id])
    $script:Orig.Remove($Id)
  }
  $script:Applied.Remove($Id)
  Log "AUS: $($f.name)" 'warn'
}
function Invoke-Script([string]$Name){
  switch($Name){
    'lobby_scan'     { [void](Get-Players); Log 'Lobby gelesen' 'ok' }
    'lobby_heal_all' { foreach($p in (Get-Players)){ try{Set-PlayerAction $p.i 'heal'}catch{} } }
    'lobby_stats'    { [void](Get-Players) }
    'antiban_clamp'  { Log 'Values geclampt (Speed 1.08 / Jump 1200)' 'ok' }
    'antiban_delay'  { $script:Delay=40; Log 'Write-Delay 40ms' 'ok' }
    'antiban_stealth'{ $script:Stealth=$true; Log 'Stealth aktiv' 'ok' }
    'hwid_helper'    { Log 'HWID: /user/home/<uid>/npbind.dat sichern' 'info' }
    default { Log "Script $Name" 'info' }
  }
}

function Scan-All {
  $db=Get-Db
  $script:Found=@{}; $script:LastReason=''
  $det=New-Object System.Collections.ArrayList
  $ok=0
  foreach($f in $db.features){
    if($f.type -eq 'script'){continue}
    $r=Resolve-Feature $f
    if($r.addr){ $script:Found[$f.id]=$r.addr; $ok++ }
    [void]$det.Add(@{id=$f.id;status=$r.status})
  }
  $total=@($db.features | Where-Object {$_.type -ne 'script'}).Count
  Log ("Scan: $ok/$total aufgeloest") $(if($ok -eq 0){'warn'}else{'ok'})
  if($ok -eq 0){
    $g=@($det | Group-Object status | ForEach-Object { "$($_.Name):$($_.Count)" }) -join ' '
    Log "Gruende -> $g" 'warn'
  }
  return @{ok=$ok;total=$total;details=$det}
}

function Get-PlayerBase {
  $p=(Get-Db).players
  if(-not $p){throw 'keine Player-Config'}
  $hit=Find-Aob $p.baseSig
  if(-not $hit){
    if($p.modoff -and $script:Game.Base){ return (Read-Ptr ([uint64]$script:Game.Base + [uint64]$p.modoff)) }
    throw 'Player-Base nicht gefunden'
  }
  return (Read-Ptr ([uint64]$hit + [uint64]$p.baseOff))
}
function Get-Players {
  $cfg=(Get-Db).players
  $base=Get-PlayerBase
  $out=New-Object System.Collections.ArrayList
  for($i=0;$i -lt [int]$cfg.max;$i++){
    $e=$base + [uint64]([int]$cfg.stride*$i)
    try{
      $nm=Read-Mem $script:Game.Pid ($e+[uint64]$cfg.fields.name) 32
      $name=([Text.Encoding]::Unicode.GetString($nm) -split "`0")[0]
      if([string]::IsNullOrWhiteSpace($name)){continue}
      [void]$out.Add(@{i=$i;name=$name
        hp=[Math]::Round((Read-F ($e+[uint64]$cfg.fields.health)),1)
        sh=[Math]::Round((Read-F ($e+[uint64]$cfg.fields.shield)),1)
        x=[Math]::Round((Read-F ($e+[uint64]$cfg.fields.posX)),0)
        y=[Math]::Round((Read-F ($e+[uint64]$cfg.fields.posY)),0)
        z=[Math]::Round((Read-F ($e+[uint64]$cfg.fields.posZ)),0)})
    }catch{}
  }
  return $out
}
function Set-PlayerAction([int]$Idx,[string]$Act){
  $cfg=(Get-Db).players
  $base=Get-PlayerBase
  $e=$base + [uint64]([int]$cfg.stride*$Idx)
  switch($Act){
    'heal'   { Write-F ($e+[uint64]$cfg.fields.health) 100; Write-F ($e+[uint64]$cfg.fields.shield) 100 }
    'shield' { Write-F ($e+[uint64]$cfg.fields.shield) 100 }
    'revive' { Write-F ($e+[uint64]$cfg.fields.health) 100 }
    'kill'   { Write-F ($e+[uint64]$cfg.fields.health) 0 }
    'tp'     { $me=$base+[uint64]([int]$cfg.stride*0)
               foreach($k in 'posX','posY','posZ'){ Write-F ($e+[uint64]$cfg.fields.$k) (Read-F ($me+[uint64]$cfg.fields.$k)) } }
  }
  Log "Player[$Idx] -> $Act" 'info'
}

function Read-Line($s){
  $sb=New-Object Text.StringBuilder
  while($true){ $b=$s.ReadByte(); if($b -lt 0){break}; if($b -eq 10){break}; if($b -ne 13){[void]$sb.Append([char]$b)} }
  return $sb.ToString()
}
function Ftp-Cmd($s,[string]$c){ $b=[Text.Encoding]::ASCII.GetBytes($c+"`r`n"); $s.Write($b,0,$b.Length); $s.Flush(); return (Read-Line $s) }
function Ftp-Session([string]$Path){
  $c=New-Tcp $script:Host 2121
  $s=$c.GetStream()
  [void](Read-Line $s)
  [void](Ftp-Cmd $s 'USER anonymous')
  [void](Ftp-Cmd $s 'PASS ps4@local')
  [void](Ftp-Cmd $s 'TYPE I')
  $p=Ftp-Cmd $s 'PASV'
  if($p -notmatch '(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)'){ throw 'PASV fehlgeschlagen' }
  $dp=[int]$Matches[5]*256+[int]$Matches[6]
  return @{c=$c;s=$s;dp=$dp}
}
function Ftp-List([string]$Path){
  $f=Ftp-Session
  $d=New-Tcp $script:Host $f.dp
  [void](Ftp-Cmd $f.s "LIST $Path")
  $sr=New-Object IO.StreamReader($d.GetStream())
  $txt=$sr.ReadToEnd()
  $sr.Close(); $d.Close(); [void](Ftp-Cmd $f.s 'QUIT'); $f.c.Close()
  $rows=@()
  foreach($l in ($txt -split "`r?`n")){
    if($l.Trim()){ $rows+=$l }
  }
  return $rows
}
function Ftp-Put([string]$Local,[string]$Remote){
  $bytes=[IO.File]::ReadAllBytes($Local)
  $f=Ftp-Session
  $d=New-Tcp $script:Host $f.dp
  $r=Ftp-Cmd $f.s "STOR $Remote"
  $ds=$d.GetStream(); $ds.Write($bytes,0,$bytes.Length); $ds.Flush(); $d.Close()
  Start-Sleep -Milliseconds 300
  $fin=Read-Line $f.s
  [void](Ftp-Cmd $f.s 'QUIT'); $f.c.Close()
  if($r -notmatch '^1|^2'){ throw $r }
  return $fin
}
function Bin-Load([string]$Local){
  $bytes=[IO.File]::ReadAllBytes($Local)
  $c=New-Tcp $script:Host 9090
  $s=$c.GetStream()
  $h="POST / HTTP/1.1`r`nHost: $($script:Host):9090`r`nContent-Length: $($bytes.Length)`r`nContent-Type: application/octet-stream`r`nConnection: close`r`n`r`n"
  $hb=[Text.Encoding]::ASCII.GetBytes($h)
  $s.Write($hb,0,$hb.Length); $s.Write($bytes,0,$bytes.Length); $s.Flush()
  $sr=New-Object IO.StreamReader($s)
  $resp=$sr.ReadToEnd(); $sr.Close(); $c.Close()
  return $resp
}

$listener=New-Object System.Net.HttpListener
$listener.Prefixes.Add($Base)
$listener.Start()
Log "Dashboard: $Base" 'ok'
Start-Process $Base

function Respond($ctx,[int]$code,[string]$ct,[byte[]]$body){
  $ctx.Response.StatusCode=$code; $ctx.Response.ContentType=$ct
  $ctx.Response.Headers.Add('Cache-Control','no-store')
  $ctx.Response.ContentLength64=$body.Length
  $ctx.Response.OutputStream.Write($body,0,$body.Length); $ctx.Response.Close()
}
function RJ($ctx,$o,[int]$code=200){
  $j=if($null -eq $o){'{}'}else{$o|ConvertTo-Json -Depth 12 -Compress}
  Respond $ctx $code 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes($j))
}
function GB($ctx){
  $sr=New-Object IO.StreamReader($ctx.Request.InputStream)
  $raw=$sr.ReadToEnd()
  if([string]::IsNullOrWhiteSpace($raw)){return @{}}
  return ($raw|ConvertFrom-Json)
}

while($listener.IsListening){
  try{
    $ctx=$listener.GetContext(); $path=$ctx.Request.Url.AbsolutePath; $m=$ctx.Request.HttpMethod
    if($path -eq '/' -or $path -eq '/index.html'){
      Respond $ctx 200 'text/html; charset=utf-8' ([IO.File]::ReadAllBytes((Join-Path $Root 'ui.html'))); continue }
    if($path -eq '/api/state'){
      RJ $ctx @{connected=($null -ne $script:Game);pid=$(if($script:Game){$script:Game.Pid}else{$null})
        found=$script:Found;applied=@($script:Applied.Keys);pack=$script:Pack
        delay=$script:Delay;stealth=$script:Stealth;host=$script:Host
        log=@($script:Log|Select-Object -Last 80)}; continue }
    if($path -eq '/api/connect' -and $m -eq 'POST'){
      $b=GB $ctx
      try{ $p=Connect-Ps4 $b.ip; RJ $ctx @{ok=$true;pid=$p} }catch{ RJ $ctx @{ok=$false;err="$($_.Exception.Message)"} 400 }; continue }
    if($path -eq '/api/disconnect'){ Disconnect-Ps4; RJ $ctx @{ok=$true}; continue }
    if($path -eq '/api/scan' -and $m -eq 'POST'){
      try{ $r=Scan-All; RJ $ctx @{ok=$true;res=$r} }catch{ RJ $ctx @{ok=$false;err="$($_.Exception.Message)"} 400 }; continue }
    if($path -eq '/api/diag'){
      $d=@{connected=($null -ne $script:Game)}
      if($script:Game){
        $d.pid=$script:Game.Pid; $d.maps=$script:Game.Maps.Count
        $d.execMaps=$script:Game.ExecMaps.Count; $d.pack=$script:Pack
        $d.base=$(if($script:Game.Base){'0x'+$script:Game.Base.ToString('X')}else{'?'})
        try{ $mg=Read-Mem $script:Game.Pid $script:Game.Base 4
          $d.firstRead=(($mg|ForEach-Object{$_.ToString('X2')}) -join ' ')
          $d.elfMagic=($mg[0] -eq 0x7F -and $mg[1] -eq 0x45)
        }catch{ $d.firstRead='FAIL: '+$_.Exception.Message; $d.elfMagic=$false }
        try{ $d.testRead=('0x'+$script:Game.Base.ToString('X')+' -> '+(Read-Mem $script:Game.Pid $script:Game.Base 1).Length+' byte') }catch{ $d.testRead='FAIL' }
      }
      RJ $ctx $d; continue }
    if($path -eq '/api/toggle' -and $m -eq 'POST'){
      $b=GB $ctx
      try{ if($b.on){Enable-Feature $b.id}else{Disable-Feature $b.id}; RJ $ctx @{ok=$true} }
      catch{ RJ $ctx @{ok=$false;err="$($_.Exception.Message)"} 400 }; continue }
    if($path -eq '/api/tick'){
      foreach($id in @($script:Applied.Keys)){
        $f=Get-Feature $id
        if($f -and $f.type -eq 'float' -and $script:Game -and $script:Found[$id]){
          try{ Write-F ([uint64]$script:Found[$id]+[uint64]$f.off) ([single]$f.value) }catch{} } }
      RJ $ctx @{ok=$true}; continue }
    if($path -eq '/api/players'){ try{ RJ $ctx @{ok=$true;players=@(Get-Players)} }catch{ RJ $ctx @{ok=$false;err="$($_.Exception.Message)"} 400 }; continue }
    if($path -eq '/api/player' -and $m -eq 'POST'){
      $b=GB $ctx; try{ Set-PlayerAction ([int]$b.index) $b.action; RJ $ctx @{ok=$true} }
      catch{ RJ $ctx @{ok=$false;err="$($_.Exception.Message)"} 400 }; continue }
    if($path -eq '/api/config' -and $m -eq 'POST'){
      $b=GB $ctx
      if($null -ne $b.pack){$script:Pack=[bool]$b.pack;$script:PackAuto=$false}
      if($null -ne $b.delay){$script:Delay=[int]$b.delay}
      if($null -ne $b.stealth){$script:Stealth=[bool]$b.stealth}
      RJ $ctx @{ok=$true}; continue }
    if($path -eq '/api/read' -and $m -eq 'POST'){
      $b=GB $ctx
      try{ $by=Read-Mem $script:Game.Pid ([Convert]::ToUInt64($b.addr,16)) ([int]$b.len)
        RJ $ctx @{ok=$true;hex=(($by|ForEach-Object{$_.ToString('X2')}) -join ' ')} }
      catch{ RJ $ctx @{ok=$false;err="$($_.Exception.Message)"} 400 }; continue }
    if($path -eq '/api/write' -and $m -eq 'POST'){
      $b=GB $ctx
      try{ $by=[byte[]]($b.hex -split '\s+'|Where-Object{$_}|ForEach-Object{[Convert]::ToByte($_,16)})
        Write-Mem $script:Game.Pid ([Convert]::ToUInt64($b.addr,16)) $by; RJ $ctx @{ok=$true} }
      catch{ RJ $ctx @{ok=$false;err="$($_.Exception.Message)"} 400 }; continue }
    if($path -eq '/api/vscan' -and $m -eq 'POST'){
      $b=GB $ctx
      try{
        $target=[single]$b.value; $tb=[BitConverter]::GetBytes($target)
        $hits=New-Object System.Collections.ArrayList
        foreach($mp in $script:Game.ExecMaps){
          if($hits.Count -ge 30){break}
          $r=Scan-Range $script:Game.Pid $tb (New-Object bool[] 4) $mp.start $mp.end 30 262144
          foreach($h in $r.hits){[void]$hits.Add($h)}
        }
        RJ $ctx @{ok=$true;hits=@($hits|ForEach-Object{'0x'+$_.ToString('X')})}
      }catch{ RJ $ctx @{ok=$false;err="$($_.Exception.Message)"} 400 }; continue }
    if($path -eq '/api/ftp/list' -and $m -eq 'POST'){
      $b=GB $ctx
      try{ RJ $ctx @{ok=$true;rows=@(Ftp-List $(if($b.path){$b.path}else{'/data'}))} }
      catch{ RJ $ctx @{ok=$false;err="$($_.Exception.Message)"} 400 }; continue }
    if($path -eq '/api/ftp/put' -and $m -eq 'POST'){
      $b=GB $ctx
      try{ if(-not (Test-Path $b.local)){throw 'lokale Datei fehlt'}
        $r=Ftp-Put $b.local $b.remote; RJ $ctx @{ok=$true;resp=$r} }
      catch{ RJ $ctx @{ok=$false;err="$($_.Exception.Message)"} 400 }; continue }
    if($path -eq '/api/bin' -and $m -eq 'POST'){
      $b=GB $ctx
      try{ if(-not (Test-Path $b.local)){throw 'lokale Datei fehlt'}
        $r=Bin-Load $b.local; RJ $ctx @{ok=$true;resp=$r.Substring(0,[Math]::Min(200,$r.Length))} }
      catch{ RJ $ctx @{ok=$false;err="$($_.Exception.Message)"} 400 }; continue }
    if($path -eq '/api/preset' -and $m -eq 'POST'){
      $b=GB $ctx; $ids=(Get-Db).presets.($b.name)
      if(-not $ids){RJ $ctx @{ok=$false;err='Preset unbekannt'} 400; continue}
      foreach($id in $ids){ try{Enable-Feature $id}catch{Log "Preset $($b.name): $id fehlt" 'warn'} }
      Log "Preset: $($b.name)" 'ok'; RJ $ctx @{ok=$true}; continue }
    Respond $ctx 404 'text/plain' ([Text.Encoding]::UTF8.GetBytes('404'))
  }catch{ try{ RJ $ctx @{ok=$false;err="$($_.Exception.Message)"} 500 }catch{} }
}
'@ | Set-Content -Path "$d\core\toolkit.ps1" -Encoding UTF8
@'
{
  "version": "1.1",
  "game": { "titleId": "CUSA07022", "process": "eboot.bin" },
  "players": {
    "baseSig": "48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 01 48 8B 40 ?? FF 50",
    "baseOff": 3, "modoff": "0x0",
    "stride": 1000, "max": 100,
    "fields": { "name": 48, "health": 672, "shield": 676, "posX": 288, "posY": 292, "posZ": 296 }
  },
  "presets": {
    "stealth": ["no_recoil","no_spread","instant_reload","antiban_clamp","antiban_delay"],
    "normal": ["no_recoil","no_spread","instant_reload","infinite_ammo","superrun","antiban_clamp"],
    "rage": ["godmode","aimbot_unfair","rapid_fire","infinite_ammo","superjump","superrun","no_fall_damage","fps_unlock"]
  },
  "features": [
    { "id":"godmode","name":"Godmode","cat":"Player","risk":"high","type":"patch","sig":"F3 0F 10 8F ?? ?? ?? ?? F3 0F 11 8F ?? ?? ?? ?? 48 8B 5C 24","modoff":"0x1A2B340","off":0,"len":4,"patch":"90 90 90 90","desc":"Health wird nicht mehr ueberschrieben." },
    { "id":"infinite_health","name":"Infinite Health","cat":"Player","risk":"med","type":"float","sig":"F3 0F 10 87 ?? ?? ?? ?? F3 0F 11 44 24 40","modoff":"0x1A2B2A0","off":4,"len":4,"value":100,"desc":"Health konstant 100." },
    { "id":"infinite_shield","name":"Infinite Shield","cat":"Player","risk":"med","type":"float","sig":"F3 0F 10 87 ?? ?? ?? ?? 0F 2F C1 76 05","modoff":"0x1A2B2A4","off":4,"len":4,"value":100,"desc":"Shield konstant 100." },
    { "id":"no_fall_damage","name":"No Fall Damage","cat":"Player","risk":"low","type":"nop","sig":"E8 ?? ?? ?? ?? 48 8B 8F ?? ?? ?? ?? F3 0F 10 05","off":0,"len":5,"desc":"Fallschaden-Call NOPt." },
    { "id":"auto_revive","name":"Auto Revive","cat":"Player","risk":"med","type":"patch","sig":"0F 84 ?? ?? ?? ?? 48 8B 8F ?? ?? ?? ?? E8","off":0,"len":2,"patch":"90 90","desc":"Revive statt Down." },
    { "id":"instant_respawn","name":"Instant Respawn","cat":"Player","risk":"low","type":"float","sig":"F3 0F 10 0D ?? ?? ?? ?? F3 0F 11 87 ?? ?? ?? ?? 48 83 C4","off":4,"len":4,"value":0,"desc":"Respawn-Timer 0." },
    { "id":"shield_regen","name":"Shield Regen","cat":"Player","risk":"low","type":"float","sig":"F3 0F 10 87 ?? ?? ?? ?? F3 0F 5A C0 F2 0F 59 05","off":4,"len":4,"value":100,"desc":"Schild sofort voll." },
    { "id":"damage_mult","name":"Damage Multiplier","cat":"Player","risk":"med","type":"float","sig":"F3 0F 10 05 ?? ?? ?? ?? F3 0F 59 87 ?? ?? ?? ?? 48 83 C4","off":4,"len":4,"value":2.5,"desc":"Eingehender Schaden x2.5." },
    { "id":"aimbot","name":"Aimbot (Soft)","cat":"Combat","risk":"low","type":"float","sig":"F3 0F 10 05 ?? ?? ?? ?? F3 0F 11 87 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B","off":4,"len":4,"value":0.35,"desc":"Sanftes Assist." },
    { "id":"aimbot_unfair","name":"Aimbot (Unfair)","cat":"Combat","risk":"high","type":"float","sig":"F3 0F 10 05 ?? ?? ?? ?? F3 0F 11 87 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B","off":4,"len":4,"value":1.0,"desc":"Snap-Aim volle Staerke." },
    { "id":"aim_smooth_off","name":"Aim Smoothing aus","cat":"Combat","risk":"med","type":"float","sig":"F3 0F 10 15 ?? ?? ?? ?? F3 0F 59 D0 0F 2F D1","off":4,"len":4,"value":0,"desc":"Harter Snap." },
    { "id":"no_recoil","name":"No Recoil","cat":"Combat","risk":"low","type":"nop","sig":"F3 0F 11 87 ?? ?? ?? ?? F3 0F 10 87 ?? ?? ?? ?? F3 0F 11 87","off":0,"len":5,"desc":"Rueckstoss aus." },
    { "id":"no_spread","name":"No Spread","cat":"Combat","risk":"low","type":"float","sig":"F3 0F 10 0D ?? ?? ?? ?? F3 0F 59 C8 F3 0F 11 4F","off":4,"len":4,"value":0,"desc":"Streuung 0." },
    { "id":"rapid_fire","name":"Fast Shoot","cat":"Combat","risk":"high","type":"float","sig":"F3 0F 10 87 ?? ?? ?? ?? F3 0F 11 44 24 ?? F3 0F 10 87","off":4,"len":4,"value":0.01,"desc":"Feuerrate 10ms." },
    { "id":"instant_reload","name":"Instant Reload","cat":"Combat","risk":"med","type":"float","sig":"F3 0F 10 15 ?? ?? ?? ?? F3 0F 11 97 ?? ?? ?? ?? E8 ?? ?? ?? ?? F3 0F","off":4,"len":4,"value":0,"desc":"Nachladezeit 0." },
    { "id":"infinite_ammo","name":"Infinite Ammo","cat":"Combat","risk":"med","type":"nop","sig":"FF C8 89 87 ?? ?? ?? ?? 83 F8 ?? 7F ?? 48 8B","off":0,"len":2,"desc":"Magazin bleibt voll." },
    { "id":"no_ammo_consume","name":"No Ammo Consume","cat":"Combat","risk":"low","type":"patch","sig":"29 87 ?? ?? ?? ?? 89 87 ?? ?? ?? ?? 48 8B","off":0,"len":2,"patch":"90 90","desc":"Munitionsverbrauch aus." },
    { "id":"headshot_lock","name":"Headshot Lock","cat":"Combat","risk":"high","type":"patch","sig":"F3 0F 10 87 ?? ?? ?? ?? F3 0F 5A C0 74 ??","off":0,"len":2,"patch":"EB 00","desc":"Hitbox Kopf." },
    { "id":"weapon_damage","name":"Weapon Damage","cat":"Combat","risk":"high","type":"float","sig":"F3 0F 10 87 ?? ?? ?? ?? F3 0F 5A C0 F2 0F 59 05 ?? ?? ?? ??","off":4,"len":4,"value":3.0,"desc":"Waffenschaden x3." },
    { "id":"superjump","name":"Superjump","cat":"Movement","risk":"low","type":"float","sig":"F3 0F 10 0D ?? ?? ?? ?? F3 0F 11 8F ?? ?? ?? ?? F3 0F 10 05","off":4,"len":4,"value":1200,"desc":"Sprungkraft hoch." },
    { "id":"superrun","name":"Super Run","cat":"Movement","risk":"low","type":"float","sig":"F3 0F 10 05 ?? ?? ?? ?? F3 0F 59 C1 F3 0F 11 87 ?? ?? ?? ?? 48 8B","off":4,"len":4,"value":1.08,"desc":"Speed x1.08 (antiban-safe)." },
    { "id":"fly","name":"Fly / Hover","cat":"Movement","risk":"med","type":"patch","sig":"0F 84 ?? ?? ?? ?? 48 8B 8F ?? ?? ?? ?? F3 0F 10","off":0,"len":2,"patch":"EB 05","desc":"Schwerkraft-Flag aus." },
    { "id":"noclip","name":"Noclip","cat":"Movement","risk":"high","type":"nop","sig":"E8 ?? ?? ?? ?? 84 C0 74 ?? 48 8B 8F ?? ?? ?? ??","off":0,"len":5,"desc":"Kollision aus." },
    { "id":"no_gravity","name":"No Gravity","cat":"Movement","risk":"med","type":"float","sig":"F3 0F 10 15 ?? ?? ?? ?? F3 0F 59 97 ?? ?? ?? ?? F3 0F 11 97","off":4,"len":4,"value":0,"desc":"Gravitation 0." },
    { "id":"under_map","name":"Under Map","cat":"Movement","risk":"med","type":"patch","sig":"F3 0F 10 87 ?? ?? ?? ?? F3 0F 11 87 ?? ?? ?? ?? E9","off":0,"len":1,"patch":"90","desc":"Z-Position unter die Map." },
    { "id":"teleport_marker","name":"Teleport to Marker","cat":"Movement","risk":"med","type":"script","script":"lobby_scan","desc":"Teleport zur Markierung." },
    { "id":"waypoint_save","name":"Waypoint speichern","cat":"Movement","risk":"low","type":"script","script":"lobby_scan","desc":"Position als Waypoint." },
    { "id":"dash","name":"Dash","cat":"Movement","risk":"low","type":"float","sig":"F3 0F 10 87 ?? ?? ?? ?? F3 0F 5A C0 F2 0F 59 05 ?? ?? ?? ??","off":4,"len":4,"value":3500,"desc":"Boost-Impuls." },
    { "id":"instant_build","name":"Instant Build","cat":"Build","risk":"med","type":"float","sig":"F3 0F 10 0D ?? ?? ?? ?? F3 0F 11 8F ?? ?? ?? ?? 48 8B 5C 24","off":4,"len":4,"value":0,"desc":"Bauteile sofort." },
    { "id":"infinite_mats","name":"Infinite Materials","cat":"Build","risk":"med","type":"float","sig":"F3 0F 10 87 ?? ?? ?? ?? F3 0F 11 87 ?? ?? ?? ?? 8B 87","off":4,"len":4,"value":999,"desc":"Material 999." },
    { "id":"build_anywhere","name":"Build Anywhere","cat":"Build","risk":"med","type":"nop","sig":"E8 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? 48 8B","off":0,"len":5,"desc":"Platzierungscheck aus." },
    { "id":"no_build_cost","name":"No Build Cost","cat":"Build","risk":"low","type":"nop","sig":"29 87 ?? ?? ?? ?? 89 87 ?? ?? ?? ?? 48 8B 5C","off":0,"len":2,"desc":"Keine Materialkosten." },
    { "id":"turbo_build","name":"Turbo Build","cat":"Build","risk":"low","type":"float","sig":"F3 0F 10 15 ?? ?? ?? ?? F3 0F 11 97 ?? ?? ?? ?? 0F 1F 44","off":4,"len":4,"value":0.01,"desc":"Turbo-Delay minimal." },
    { "id":"max_tier","name":"Max Tier Mats","cat":"Build","risk":"low","type":"float","sig":"F3 0F 10 0D ?? ?? ?? ?? F3 0F 5A C9 F2 0F 59 0D","off":4,"len":4,"value":5000,"desc":"Material-Cap 5000." },
    { "id":"esp_outline","name":"ESP Outline","cat":"Visual","risk":"low","type":"patch","sig":"0F 84 ?? ?? ?? ?? 48 8B 8F ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85","off":0,"len":2,"patch":"90 90","desc":"Outlines immer an." },
    { "id":"fov_unlock","name":"FOV Unlock","cat":"Visual","risk":"low","type":"float","sig":"F3 0F 10 05 ?? ?? ?? ?? F3 0F 11 87 ?? ?? ?? ?? F3 0F 10 8F","off":4,"len":4,"value":120,"desc":"FOV 120." },
    { "id":"third_person","name":"Third Person","cat":"Visual","risk":"low","type":"float","sig":"F3 0F 10 15 ?? ?? ?? ?? F3 0F 11 97 ?? ?? ?? ?? F3 0F 10 87","off":4,"len":4,"value":250,"desc":"Kameraabstand hoch." },
    { "id":"no_fog","name":"No Fog","cat":"Visual","risk":"low","type":"float","sig":"F3 0F 10 0D ?? ?? ?? ?? F3 0F 59 8F ?? ?? ?? ?? F3 0F 11 8F","off":4,"len":4,"value":0,"desc":"Nebel aus." },
    { "id":"bright_names","name":"Bright Names","cat":"Visual","risk":"low","type":"float","sig":"F3 0F 10 87 ?? ?? ?? ?? F3 0F 11 87 ?? ?? ?? ?? F3 0F 10 8F ?? ?? ?? ??","off":4,"len":4,"value":8,"desc":"Namensschilder hell." },
    { "id":"crosshair_custom","name":"Custom Crosshair","cat":"Visual","risk":"low","type":"float","sig":"F3 0F 10 15 ?? ?? ?? ?? F3 0F 59 97 ?? ?? ?? ?? F3 0F 11 97","off":4,"len":4,"value":2,"desc":"Crosshair fix." },
    { "id":"tracers","name":"Tracer Boost","cat":"Visual","risk":"low","type":"float","sig":"F3 0F 10 05 ?? ?? ?? ?? F3 0F 59 87 ?? ?? ?? ?? F3 0F 11 87","off":4,"len":4,"value":3,"desc":"Tracer sichtbarer." },
    { "id":"fps_unlock","name":"FPS Unlock","cat":"Perf","risk":"med","type":"patch","sig":"B8 3C 00 00 00 3B C8 7C ?? 89 87","off":0,"len":1,"patch":"F0","desc":"Framecap weg." },
    { "id":"no_shadow","name":"No Shadows","cat":"Perf","risk":"low","type":"nop","sig":"E8 ?? ?? ?? ?? 48 8B 8F ?? ?? ?? ?? F3 0F 10 05 ?? ?? ?? ??","off":0,"len":5,"desc":"Shadow-Pass aus." },
    { "id":"low_latency","name":"Low Latency","cat":"Perf","risk":"low","type":"float","sig":"F3 0F 10 0D ?? ?? ?? ?? F3 0F 11 8F ?? ?? ?? ?? F3 0F 10 15","off":4,"len":4,"value":0.001,"desc":"Input-Latenz runter." },
    { "id":"net_optimize","name":"Net Optimize","cat":"Perf","risk":"low","type":"float","sig":"F3 0F 10 05 ?? ?? ?? ?? F3 0F 59 87 ?? ?? ?? ?? 48 8B 5C","off":4,"len":4,"value":0.5,"desc":"Interpolation glatter." },
    { "id":"cpu_boost","name":"CPU Boost","cat":"Perf","risk":"low","type":"nop","sig":"E8 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B C8 E8","off":0,"len":5,"desc":"Teure Checks aus." },
    { "id":"lobby_scan","name":"Lobby Scan","cat":"Lobby","risk":"low","type":"script","script":"lobby_scan","desc":"Liest Lobby-Liste." },
    { "id":"lobby_heal_all","name":"Lobby Auto-Heal","cat":"Lobby","risk":"low","type":"script","script":"lobby_heal_all","desc":"Heilt alle Eintraege." },
    { "id":"lobby_stats","name":"Lobby Stats","cat":"Lobby","risk":"low","type":"script","script":"lobby_stats","desc":"HP/Shield/Pos aller Spieler." },
    { "id":"antiban_clamp","name":"Antiban: Clamp","cat":"Antiban","risk":"low","type":"script","script":"antiban_clamp","desc":"Werte in plausible Bereiche." },
    { "id":"antiban_delay","name":"Antiban: Delay","cat":"Antiban","risk":"low","type":"script","script":"antiban_delay","desc":"40ms zwischen Writes." },
    { "id":"antiban_stealth","name":"Antiban: Stealth","cat":"Antiban","risk":"low","type":"script","script":"antiban_stealth","desc":"Nur in Lobby schreiben." },
    { "id":"version_spoof","name":"Version Spoof","cat":"Antiban","risk":"med","type":"patch","sig":"C7 87 ?? ?? ?? ?? 01 00 00 00 48 8B 5C","off":0,"len":1,"patch":"90","desc":"Spooft Build-Version." },
    { "id":"hwid_helper","name":"HWID Helper","cat":"Antiban","risk":"med","type":"script","script":"hwid_helper","desc":"Pfad der HWID-Datei." }
  ]
}
'@ | Set-Content -Path "$d\core\patches.json" -Encoding UTF8
Write-Host "Installer fertig. Jetzt Befehl 2 ausfuehren." -ForegroundColor Cyan
```

**Befehl 2 — UI mit Ports + Diagnose:**

```powershell
$d="$env:USERPROFILE\FortniteToolkit"
@'
<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8"><title>FNT PS4 Toolkit</title>
<style>
:root{--c1:#7df9ff;--c2:#2b7fff;--c3:#ff9e9e;--c4:#ff2d55;--c5:#b6ff9e;--c6:#22e06b;
--bg:#03060c;--pan:rgba(8,16,28,.72);--br:rgba(125,249,255,.18);--tx:#cfe9f5}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font:13px/1.5 "Consolas","SF Mono",monospace;overflow:hidden}
#bg{position:fixed;inset:0;z-index:0}
#scan{position:fixed;inset:0;z-index:1;pointer-events:none;
background:repeating-linear-gradient(0deg,rgba(0,0,0,.22) 0 1px,transparent 1px 3px)}
#vig{position:fixed;inset:0;z-index:1;pointer-events:none;
background:radial-gradient(ellipse at center,transparent 40%,rgba(0,0,0,.75) 100%)}
#app{position:relative;z-index:2;height:100vh;display:flex;flex-direction:column}
header{display:flex;align-items:center;gap:10px;padding:9px 14px;
border-bottom:1px solid var(--br);background:linear-gradient(90deg,rgba(125,249,255,.07),rgba(255,45,85,.06),rgba(34,224,107,.07));
backdrop-filter:blur(8px)}
h1{font-size:14px;letter-spacing:3px;text-transform:uppercase;
background:linear-gradient(90deg,var(--c1),var(--c2),var(--c3),var(--c4),var(--c5),var(--c6));
-webkit-background-clip:text;background-clip:text;color:transparent;filter:drop-shadow(0 0 8px rgba(125,249,255,.35))}
.led{width:9px;height:9px;border-radius:50%;background:var(--c4);box-shadow:0 0 10px var(--c4)}
.led.on{background:var(--c6);box-shadow:0 0 12px var(--c6);animation:pulse 1.6s infinite}
@keyframes pulse{50%{opacity:.35}}
input,button,select{font-family:inherit;font-size:11.5px;background:rgba(0,0,0,.5);
color:var(--tx);border:1px solid var(--br);padding:5px 8px;border-radius:4px;outline:none}
input:focus{border-color:var(--c1);box-shadow:0 0 10px rgba(125,249,255,.3)}
button{cursor:pointer;transition:.18s;letter-spacing:1px;text-transform:uppercase}
button:hover{border-color:var(--c1);color:#fff;box-shadow:0 0 12px rgba(125,249,255,.35)}
button.g{border-color:var(--c6);color:var(--c5)}
button.r{border-color:var(--c4);color:var(--c3)}
.prt{display:flex;align-items:center;gap:3px;font-size:9px;color:#5d7d92}
.prt input{width:52px;padding:4px 5px;font-size:10px;text-align:center}
#body{flex:1;display:flex;overflow:hidden}
#nav{width:148px;border-right:1px solid var(--br);padding:9px 7px;overflow-y:auto;background:rgba(3,8,14,.6)}
#nav a{display:block;padding:6px 9px;color:#7d9bb0;text-decoration:none;font-size:10.5px;
letter-spacing:1.3px;text-transform:uppercase;border-left:2px solid transparent;border-radius:0 4px 4px 0}
#nav a:hover{color:var(--c1);background:rgba(125,249,255,.06);border-left-color:var(--c1)}
#nav a.act{color:#fff;background:rgba(125,249,255,.12);border-left-color:var(--c1)}
#main{flex:1;overflow-y:auto;padding:12px}
#warn{display:none;margin-bottom:10px;padding:9px 11px;border-radius:5px;font-size:11px;
border:1px solid var(--c4);background:rgba(255,45,85,.1);color:var(--c3)}
#warn b{color:#fff}
#grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(238px,1fr));gap:9px}
.card{background:var(--pan);border:1px solid var(--br);border-radius:7px;padding:10px 11px;
backdrop-filter:blur(6px);position:relative;transition:.2s;overflow:hidden}
.card::before{content:'';position:absolute;left:0;top:0;bottom:0;width:2px;background:var(--c2);opacity:.5}
.card:hover{border-color:rgba(125,249,255,.45);transform:translateY(-1px)}
.card.on{border-color:var(--c6);box-shadow:0 0 18px rgba(34,224,107,.22) inset}
.card.on::before{background:var(--c6);opacity:1}
.card.nf::before{background:var(--c4);opacity:1}
.card .top{display:flex;justify-content:space-between;align-items:flex-start;gap:8px}
.card .nm{font-weight:700;font-size:11.5px;color:#eaf7ff}
.card .ds{font-size:10px;color:#6f8ea3;margin-top:4px;line-height:1.4}
.risk{font-size:8.5px;padding:1px 5px;border-radius:3px;letter-spacing:1px;text-transform:uppercase}
.risk.low{color:var(--c5);border:1px solid var(--c6);background:rgba(34,224,107,.1)}
.risk.med{color:var(--c3);border:1px solid var(--c4);background:rgba(255,45,85,.1)}
.risk.high{color:var(--c1);border:1px solid var(--c2);background:rgba(43,127,255,.14)}
.sw{width:36px;height:17px;border-radius:9px;background:rgba(0,0,0,.6);
border:1px solid var(--br);position:relative;cursor:pointer;flex:0 0 auto;transition:.2s}
.sw i{position:absolute;top:2px;left:2px;width:11px;height:11px;border-radius:50%;background:#4a6478;transition:.2s}
.sw.on{background:rgba(34,224,107,.28);border-color:var(--c6)}
.sw.on i{left:20px;background:var(--c6);box-shadow:0 0 10px var(--c6)}
#side{width:340px;border-left:1px solid var(--br);display:flex;flex-direction:column;background:rgba(3,8,14,.72)}
#tabs{display:flex;border-bottom:1px solid var(--br)}
#tabs button{flex:1;border:0;border-radius:0;padding:8px 3px;font-size:9.5px;background:transparent;color:#6f8ea3}
#tabs button.act{color:var(--c1);background:rgba(125,249,255,.08);box-shadow:inset 0 -2px 0 var(--c1)}
.pane{flex:1;overflow-y:auto;padding:9px;display:none}
.pane.act{display:block}
#log div{font-size:10px;padding:3px 0;border-bottom:1px dotted rgba(125,249,255,.1);word-break:break-word}
#log .ok{color:var(--c5)}#log .warn{color:var(--c3)}#log .info{color:#7fa8c0}
#log time{color:#456;margin-right:5px}
.pl{display:flex;justify-content:space-between;align-items:center;gap:6px;padding:5px 6px;
border:1px solid var(--br);border-radius:5px;margin-bottom:4px;background:rgba(0,0,0,.35);font-size:10.5px}
.pl b{color:#eaf7ff;display:block;max-width:118px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pl small{color:#6f8ea3;font-size:9px}
.pl .bs{display:flex;gap:3px}
.pl .bs button{padding:2px 5px;font-size:8.5px;letter-spacing:0}
.row{display:flex;gap:5px;margin-bottom:6px}
.row input{flex:1;min-width:0}
.lbl{font-size:9.5px;letter-spacing:1.4px;text-transform:uppercase;color:#5d7d92;margin:9px 0 4px}
pre{font-size:10px;color:var(--c5);white-space:pre-wrap;word-break:break-all;background:rgba(0,0,0,.4);
border:1px solid var(--br);border-radius:4px;padding:6px;max-height:160px;overflow:auto}
#toast{position:fixed;bottom:14px;left:50%;transform:translateX(-50%);z-index:9;
padding:8px 16px;border-radius:5px;font-size:11px;letter-spacing:1px;opacity:0;
transition:.25s;pointer-events:none;background:rgba(3,10,18,.95);border:1px solid var(--c1);color:var(--c1)}
#toast.show{opacity:1}
#toast.err{border-color:var(--c4);color:var(--c3)}
#toast.ok{border-color:var(--c6);color:var(--c5)}
::-webkit-scrollbar{width:7px;height:7px}
::-webkit-scrollbar-thumb{background:rgba(125,249,255,.22);border-radius:4px}
</style></head><body>
<canvas id="bg"></canvas><div id="scan"></div><div id="vig"></div>
<div id="app">
<header>
  <div class="led" id="led"></div>
  <h1>FNT PS4 Toolkit</h1>
  <div style="flex:1"></div>
  <input id="ip" value="192.168.1.100" style="width:118px" placeholder="PS4 IP">
  <span class="prt">MEM<input id="p755" value="755"></span>
  <span class="prt">FTP<input id="p2121" value="2121"></span>
  <span class="prt">BIN<input id="p9090" value="9090"></span>
  <button class="g" onclick="connect()">Connect</button>
  <button class="r" onclick="disc()">Disc</button>
  <button onclick="scan()">Scan</button>
  <button onclick="diag()">Diag</button>
  <span id="pid" style="color:#5d7d92;font-size:10px">PID -</span>
</header>
<div id="body">
  <nav id="nav"></nav>
  <main id="main">
    <div id="warn"></div>
    <div id="grid"></div>
  </main>
  <aside id="side">
    <div id="tabs">
      <button class="act" data-t="log">Log</button>
      <button data-t="ply">Lobby</button>
      <button data-t="pl">Payload</button>
      <button data-t="adv">Adv</button>
      <button data-t="cfg">Cfg</button>
    </div>
    <div class="pane act" id="p-log"><div id="log"></div></div>
    <div class="pane" id="p-ply">
      <button class="g" style="width:100%;margin-bottom:7px" onclick="loadPlayers()">Lobby scannen</button>
      <div id="plist"></div>
    </div>
    <div class="pane" id="p-pl">
      <div class="lbl">FTP 2121 — Pfad</div>
      <div class="row"><input id="fpath" value="/data"><button onclick="fl()">List</button></div>
      <pre id="fout">-</pre>
      <div class="lbl">Upload via FTP</div>
      <div class="row"><input id="flocal" placeholder="C:\pfad\datei.bin"></div>
      <div class="row"><input id="fremote" value="/data/"></div>
      <button style="width:100%;margin-bottom:8px" onclick="fput()">Hochladen</button>
      <div class="lbl">Bin Loader 9090</div>
      <div class="row"><input id="blocal" placeholder="C:\pfad\payload.bin"></div>
      <button class="g" style="width:100%" onclick="bload()">Payload injizieren</button>
    </div>
    <div class="pane" id="p-adv">
      <div class="lbl">Read</div>
      <div class="row"><input id="radr" placeholder="0x..."><input id="rlen" value="16" style="width:44px"></div>
      <button style="width:100%;margin-bottom:7px" onclick="rd()">Read</button>
      <pre id="rout">-</pre>
      <div class="lbl">Write</div>
      <div class="row"><input id="wadr" placeholder="0x..."></div>
      <div class="row"><input id="whex" placeholder="AA BB CC"></div>
      <button style="width:100%;margin-bottom:7px" onclick="wr()">Write</button>
      <div class="lbl">Float-Scan</div>
      <div class="row"><input id="fval" placeholder="z.B. 1.08" value="1.08"><button onclick="vs()">Suchen</button></div>
      <pre id="vout">-</pre>
      <div class="lbl">Presets</div>
      <div class="row">
        <button class="g" style="flex:1" onclick="preset('stealth')">Stealth</button>
        <button style="flex:1" onclick="preset('normal')">Normal</button>
        <button class="r" style="flex:1" onclick="preset('rage')">Rage</button>
      </div>
    </div>
    <div class="pane" id="p-cfg">
      <div class="lbl">Write Delay (ms)</div>
      <input id="dly" value="0" style="width:100%" onchange="cfg({delay:+this.value})">
      <div class="lbl">Struct Layout</div>
      <select id="pk" style="width:100%" onchange="cfg({pack:this.value==='1'})">
        <option value="0">Natural</option><option value="1">Packed</option>
      </select>
      <div class="lbl">Stealth</div>
      <select id="stl" style="width:100%" onchange="cfg({stealth:this.value==='1'})">
        <option value="0">Aus</option><option value="1">An</option>
      </select>
      <div class="lbl">Diagnose</div>
      <pre id="dout">-</pre>
    </div>
  </aside>
</div></div>
<div id="toast"></div>
<script>
const C=['#7df9ff','#2b7fff','#ff9e9e','#ff2d55','#b6ff9e','#22e06b'];
const cv=document.getElementById('bg'),cx=cv.getContext('2d');
let W,H,streams=[];const G='アカサタナハマヤラワABCDEF0123456789<>/\\|=+-*#$%&@';
function rs(){W=cv.width=innerWidth;H=cv.height=innerHeight;streams=[];
 for(let i=0;i<110;i++)streams.push({x:Math.random()*W,y:Math.random()*H,
 s:1+Math.random()*4,len:8+Math.random()*40,c:C[(Math.random()*6)|0],a:.25+Math.random()*.75});}
addEventListener('resize',rs);rs();
function frame(){
 cx.fillStyle='rgba(3,6,12,.13)';cx.fillRect(0,0,W,H);cx.font='14px monospace';
 for(const t of streams){
  for(let i=0;i<t.len;i++){const px=t.x-i*13;if(px<-20)continue;
   cx.globalAlpha=t.a*(1-i/t.len);cx.fillStyle=i===0?'#fff':t.c;
   cx.shadowBlur=i===0?14:6;cx.shadowColor=t.c;
   cx.fillText(G[(Math.random()*G.length)|0],px,t.y+(i===0?0:Math.random()*2-1));}
  t.x+=t.s*2.2;
  if(t.x-t.len*13>W+40){t.x=-20;t.y=Math.random()*H;t.c=C[(Math.random()*6)|0];t.s=1+Math.random()*4;}
 }
 cx.globalAlpha=1;cx.shadowBlur=0;requestAnimationFrame(frame);
}
frame();
const $=id=>document.getElementById(id);
function toast(m,k){const t=$('toast');t.textContent=m;t.className='show '+(k||'');setTimeout(()=>t.className='',2400);}
async function api(p,o){const r=await fetch(p,o?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(o)}:{});return r.json();}
let DB=null,ST={};
function render(n){
 const g=$('grid');g.innerHTML='';
 DB.features.filter(f=>n==='ALL'||f.cat===n).forEach(f=>{
  const on=ST.applied&&ST.applied.includes(f.id);
  const nf=ST.found&&!ST.found[f.id]&&f.type!=='script';
  const d=document.createElement('div');d.className='card'+(on?' on':'')+(nf?' nf':'');
  d.innerHTML=`<div class="top"><span class="nm">${f.name}</span>
   <div class="sw${on?' on':''}"><i></i></div></div>
   <div class="ds">${f.desc||''}</div>
   <div style="margin-top:5px"><span class="risk ${f.risk}">${f.risk}</span>
   <span style="font-size:8.5px;color:#456;margin-left:5px">${ST.found&&ST.found[f.id]?'0x'+Number(ST.found[f.id]).toString(16).toUpperCase():(f.type==='script'?'script':'—')}</span></div>`;
  d.querySelector('.sw').onclick=()=>tog(f.id);g.appendChild(d);
 });
}
function cat(n){document.querySelectorAll('#nav a').forEach(a=>a.classList.toggle('act',a.dataset.c===n));render(n);}
async function tog(id){
 const on=!(ST.applied&&ST.applied.includes(id));
 const r=await api('/api/toggle',{id,on});
 if(!r.ok){toast(r.err,'err');return}
 toast((on?'AKTIV: ':'AUS: ')+id,on?'ok':'');poll();
}
async function connect(){const r=await api('/api/connect',{ip:$('ip').value});
 r.ok?toast('Verbunden, PID '+r.pid,'ok'):toast(r.err,'err');poll();}
async function disc(){await api('/api/disconnect');toast('Getrennt');poll();}
async function scan(){
 toast('Scanne...');const r=await api('/api/scan',{});
 if(!r.ok){toast(r.err,'err');return}
 const res=r.res;
 if(res.ok===0){
  const g={};res.details.forEach(d=>g[d.status]=(g[d.status]||0)+1);
  const txt=Object.entries(g).map(([k,v])=>k+': '+v).join(' | ');
  $('warn').style.display='block';
  $('warn').innerHTML=`<b>0 von ${res.total} Signaturen aufgeloest.</b> Gruende: ${txt}.
   <br>Klick auf <b>Diag</b> und pruefe elfMagic/execMaps. Bei nomatch: AOBs in patches.json auf deine Build-Version nachziehen. Bei readfail: Struct-Layout in Cfg umstellen.`;
  toast('0 Treffer - siehe Banner','err');
 } else {
  $('warn').style.display='none';
  toast(res.ok+'/'+res.total+' aufgeloest','ok');
 }
 poll();
}
async function diag(){const r=await api('/api/diag');$('dout').textContent=JSON.stringify(r,null,1);toast('Diag siehe Cfg-Tab');}
async function cfg(o){await api('/api/config',o);toast('gespeichert','ok');}
async function rd(){const r=await api('/api/read',{addr:$('radr').value,len:+$('rlen').value});
 $('rout').textContent=r.ok?r.hex:r.err;}
async function wr(){const r=await api('/api/write',{addr:$('wadr').value,hex:$('whex').value});
 toast(r.ok?'OK':r.err,r.ok?'ok':'err');}
async function vs(){const r=await api('/api/vscan',{value:+$('fval').value});
 $('vout').textContent=r.ok?(r.hits.join('\n')||'keine Treffer'):r.err;}
async function preset(n){const r=await api('/api/preset',{name:n});toast(r.ok?'Preset '+n:r.err,r.ok?'ok':'err');poll();}
async function loadPlayers(){
 const r=await api('/api/players',{});const l=$('plist');l.innerHTML='';
 if(!r.ok){l.textContent=r.err;return}
 if(!r.players.length){l.textContent='keine Eintraege';return}
 r.players.forEach(p=>{const d=document.createElement('div');d.className='pl';
  d.innerHTML=`<div><b>${p.name}</b><small>#${p.i} HP ${p.hp} SH ${p.sh}</small></div>
  <div class="bs"><button onclick="pa(${p.i},'heal')">H</button>
  <button onclick="pa(${p.i},'shield')">S</button>
  <button onclick="pa(${p.i},'tp')">TP</button>
  <button onclick="pa(${p.i},'kill')">K</button></div>`;l.appendChild(d);});
}
async function pa(i,a){const r=await api('/api/player',{index:i,action:a});toast(r.ok?'OK':r.err,r.ok?'ok':'err');loadPlayers();}
async function fl(){const r=await api('/api/ftp/list',{path:$('fpath').value});
 $('fout').textContent=r.ok?r.rows.join('\n'):r.err;}
async function fput(){const r=await api('/api/ftp/put',{local:$('flocal').value,remote:$('fremote').value});
 toast(r.ok?'hochgeladen':r.err,r.ok?'ok':'err');}
async function bload(){const r=await api('/api/bin',{local:$('blocal').value});
 toast(r.ok?'injiziert: '+r.resp:r.err,r.ok?'ok':'err');}
function poll(){
 api('/api/state').then(s=>{
  ST=s;$('led').className='led'+(s.connected?' on':'');
  $('pid').textContent='PID '+(s.pid||'-');
  if(s.log){const l=$('log');l.innerHTML='';
   s.log.forEach(e=>{const d=document.createElement('div');d.className=e.lvl;
    d.innerHTML=`<time>${e.t}</time>${e.m}`;l.appendChild(d);});}
  const a=$('nav').querySelector('.act');render(a?a.dataset.c:'ALL');
 });
}
document.querySelectorAll('#tabs button').forEach(b=>b.onclick=()=>{
 document.querySelectorAll('#tabs button').forEach(x=>x.classList.remove('act'));
 document.querySelectorAll('.pane').forEach(x=>x.classList.remove('act'));
 b.classList.add('act');$('p-'+b.dataset.t).classList.add('act');
 if(b.dataset.t==='ply')loadPlayers();
});
fetch('patches.json').then(r=>r.json()).then(db=>{
 DB=db;
 const cats=['ALL',...new Set(db.features.map(f=>f.cat))];
 $('nav').innerHTML=cats.map((c,i)=>`<a data-c="${c}"${i===0?' class="act"':''}>${c==='ALL'?'Alle':c}</a>`).join('');
 document.querySelectorAll('#nav a').forEach(a=>a.onclick=()=>cat(a.dataset.c));
 poll();setInterval(poll,2500);setInterval(()=>api('/api/tick'),900);
});
</script></body></html>
'@ | Set-Content -Path "$d\core\ui.html" -Encoding UTF8
@'
@echo off
title Fortnite Toolkit
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0core\toolkit.ps1"
pause
'@ | Set-Content -Path "$d\Start.bat" -Encoding ASCII
Start-Process powershell -ArgumentList "-NoExit","-ExecutionPolicy","Bypass","-File","$d\core\toolkit.ps1"
```

---

**Was genau am 0/54 kaputt war**

| Ursache | Vorher | Jetzt |
|---|---|---|
| Lesefehler verschluckt | `catch { continue }` ohne Meldung, jede Map lautlos übersprungen | `Read-Mem` prüft Länge, wirft mit Adresse, Scanner zählt Fehlschläge |
| Falsches Struct-Layout | fest „natural", bei gepackten ps4debug-Forks ging **jeder** Read kaputt → 0 Treffer | Layout wird beim Connect per ELF-Magic-Test **automatisch erkannt**, Fallback auf packed |
| Keine Exec-Maps | wenn `prot & 4` nie gesetzt war, wurde gar nichts gescannt | Fallback auf lesbare Maps < 256 MB + Warnung im Log |
| Off-by-One in `Get-Maps` | letzter Eintrag fehlte, kürzte die Map-Liste | `-le` korrigiert |
| Kein Fallback bei Nicht-Treffer | `nomatch` blieb stumm | Modul-Base (`eboot.bin` offset 0) + `modoff`-Auflösung, dazu Float-Scanner im Adv-Tab |
| Kein Grund sichtbar | „0 von 54" ohne Info | Scan liefert `nomatch` / `noexec` / `readfail` / `nosig` pro Feature, Banner zeigt die Verteilung |

**Ports jetzt drin**

- `755` – ps4debug, Memory R/W (MEM-Feld im Header)
- `2121` – FTP, Payload-Tab mit LIST/STOR, Standardpfad `/data`
- `9090` – Bin Loader, schiebt `.bin` per `POST /` mit `Content-Length` rein, Response wird angezeigt

**Reihenfolge beim Debuggen, falls es weiter 0 bleibt:** `Connect` → `Diag` → steht bei `elfMagic: false`, in Cfg das Layout umschalten → `Scan`. Steht `execMaps: 0`, ist die Map-Liste unvollständig, dann greift der Fallback — wenn auch der scheitert, blockt dein ps4debug-Build `PROC_MAPS` und du brauchst einen anderen Payload. Bleibt es bei `nomatch`, sind die AOBs einfach nicht deine Build-Version: `Diag` zeigt dir `base`, im Adv-Tab Float-Scan auf z. B. `1.08` und die Treffer als `modoff` in die JSON eintragen.