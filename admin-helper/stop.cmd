@echo off
cd /d "%~dp0"
if not exist "runtime\helper.pid" (
  echo helper.pid не найден - помощник, похоже, не запущен из этой папки.
  goto :clean
)
powershell -NoProfile -NonInteractive -Command ^
  "try {" ^
  "  $l = @(Get-Content -LiteralPath 'runtime\helper.pid');" ^
  "  if ($l.Count -lt 2 -or -not $l[1]) { Write-Host '  в helper.pid нет метки времени - останавливать по одному PID небезопасно, не трогаю'; exit 2 }" ^
  "  $id = [int]($l[0]); $want = [long]($l[1]);" ^
  "  $p = Get-Process -Id $id -ErrorAction SilentlyContinue;" ^
  "  if (-not $p) { Write-Host '  процесс не найден - уже остановлен'; exit 0 }" ^
  "  $n = ($p.ProcessName -like '*python*' -or $p.ProcessName -like '*powershell*' -or $p.ProcessName -like '*pwsh*' -or $p.ProcessName -like '*odl-helper*');" ^
  "  $t = $false; try { $t = ($p.StartTime.ToFileTimeUtc() -eq $want) } catch { $t = $false }" ^
  "  if (-not ($n -and $t)) { Write-Host '  это НЕ наш помощник (имя/время создания не совпали) - не трогаю'; exit 2 }" ^
  "  Stop-Process -InputObject $p -Force; Start-Sleep -Milliseconds 400;" ^
  "  if (Get-Process -Id $id -ErrorAction SilentlyContinue) { Write-Host '  не удалось завершить процесс'; exit 1 }" ^
  "  Write-Host ('  остановлен процесс ' + $id); exit 0" ^
  "} catch { Write-Host ('  ошибка остановки: ' + $_.Exception.Message); exit 1 }"
if errorlevel 1 (
  echo Процесс не остановлен достоверно - замок и helper.pid НЕ удаляю. Разберитесь вручную.
  goto :end
)
:clean
del /q "runtime\helper.lock" "runtime\helper.pid" >nul 2>&1
echo Готово. История НЕ удалялась. Запуск снова - run.cmd (Python) или run_ps.cmd (PowerShell).
:end
pause
