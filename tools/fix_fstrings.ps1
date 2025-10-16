# fix_fstrings.ps1 — py311-safe f-string cleaner (simple & robust)

$Report = "fstring_py311_report.md"

# Regexes to fix format-spec backslashes like {name:\t<40} or {name:\n<40}
$specFixTab = [regex]'\{([^}:]+):\\t([^}]*)\}'
$specFixNL  = [regex]'\{([^}:]+):\\n([^}]*)\}'

# Detector: any backslash inside {...} of an f-string
$exprBackslash = [regex]'\{[^}]*\\[^}]*\}'

# Comment we’ll append to lines that still need a manual change
$fixme = '# FIXME(py311-fstring-backslash): move inner expression to a temp var before the f-string.'

$hits = @()

Get-ChildItem -Recurse -File -Path "src\**\*.py" | ForEach-Object {
  $path = $_.FullName
  $lines = Get-Content $path
  $changed = $false
  $autoFixes = 0
  $out = New-Object System.Text.StringBuilder

  # One-time backup
  $bak = "$path.bak"
  if (-not (Test-Path $bak)) { Copy-Item -Force $path $bak }

  for ($i=0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]

    # Quick f-string sniff without tricky regex escaping
    if ($line.Contains('f"') -or $line.Contains("f'")) {

      # Safe auto-fix: move \t / \n out of format spec
      $fixed = $specFixTab.Replace($line, '{$1:$2}' + "`t")
      $fixed = $specFixNL.Replace($fixed,  '{$1:$2}' + "`n")
      if ($fixed -ne $line) { $line = $fixed; $changed = $true; $autoFixes++ }

      # Report remaining backslashes inside {...}
      if ([regex]::IsMatch($line, $exprBackslash)) {
        if (-not ($line.TrimEnd().EndsWith($fixme))) {
          $line = $line + "  $fixme"
          $changed = $true
        }
        $ctx = ($lines[[Math]::Max(0,$i-1)..[Math]::Min($lines.Count-1,$i+1)] -join "`n")
        $hits += [pscustomobject]@{ File=$path; Line=$i+1; Snip=$ctx }
      }
    }

    [void]$out.AppendLine($line)
  }

  if ($changed) {
    $newText = $out.ToString()
    Set-Content -Path $path -Value $newText -Encoding UTF8
    Write-Host "Updated: $($path)  (auto-fixes: $autoFixes)"
  }
}

# Write report if anything still needs manual edits
if ($hits.Count) {
  "# py311 f-string backslash report`n" | Set-Content $Report -Encoding UTF8
  "Move the inner expression to a temp variable, then use that var in the f-string." | Add-Content $Report
  "" | Add-Content $Report
  $hits | Sort-Object File,Line | ForEach-Object {
    "### $($_.File):$($_.Line)" | Add-Content $Report
    '```python'                  | Add-Content $Report
    $_.Snip                      | Add-Content $Report
    '```'                        | Add-Content $Report
    ""                           | Add-Content $Report
  }
  Write-Host "Report written: $Report"
} else {
  Write-Host "No remaining f-string backslash expressions found 🎉"
}
