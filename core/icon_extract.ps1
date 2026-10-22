param(
    [Parameter(Mandatory = $true)][string]$InputFile,
    [Parameter(Mandatory = $true)][string]$OutputFile
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class SoftSweepIconNative {
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint PrivateExtractIcons(
        string lpszFile, int nIconIndex, int cxIcon, int cyIcon,
        IntPtr[] phicon, uint[] piconid, uint nIcons, uint flags);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool DestroyIcon(IntPtr hIcon);
}
'@

$tasks = Get-Content -LiteralPath $InputFile -Raw -Encoding UTF8 | ConvertFrom-Json
$results = @()

foreach ($task in $tasks) {
    $dest = [string]$task.dest
    $ok = $false
    $reason = '没有可用的图标来源'

    foreach ($src in @($task.sources)) {
        if ($ok) { break }
        try {
            $path = [string]$src.path
            if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
                $reason = '图标来源文件不存在'
                continue
            }

            $bitmap = $null
            if ([string]$src.type -eq 'image') {
                $image = [System.Drawing.Image]::FromFile($path)
                try {
                    $bitmap = New-Object System.Drawing.Bitmap($image.Width, $image.Height)
                    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
                    try {
                        $graphics.DrawImage($image, 0, 0, $image.Width, $image.Height)
                    } finally {
                        $graphics.Dispose()
                    }
                } finally {
                    $image.Dispose()
                }
            } else {
                $index = 0
                if ($null -ne $src.index) {
                    try { $index = [int]$src.index } catch { $index = 0 }
                }

                $hicons = New-Object IntPtr[] 1
                $iconIds = New-Object UInt32[] 1
                $count = [SoftSweepIconNative]::PrivateExtractIcons(
                    $path, $index, 256, 256, $hicons, $iconIds, 1, 0)
                if (($count -le 0 -or $hicons[0] -eq [IntPtr]::Zero) -and $index -ne 0) {
                    $count = [SoftSweepIconNative]::PrivateExtractIcons(
                        $path, 0, 256, 256, $hicons, $iconIds, 1, 0)
                }
                if ($count -le 0 -or $hicons[0] -eq [IntPtr]::Zero) {
                    $count = [SoftSweepIconNative]::PrivateExtractIcons(
                        $path, 0, 64, 64, $hicons, $iconIds, 1, 0)
                }
                if ($count -le 0 -or $hicons[0] -eq [IntPtr]::Zero) {
                    $reason = '无法从文件中提取图标资源'
                    continue
                }

                $icon = [System.Drawing.Icon]::FromHandle($hicons[0])
                try {
                    $bitmap = $icon.ToBitmap()
                } finally {
                    $icon.Dispose()
                    [SoftSweepIconNative]::DestroyIcon($hicons[0]) | Out-Null
                }
            }

            if ($null -eq $bitmap -or $bitmap.Width -le 0 -or $bitmap.Height -le 0) {
                $reason = '图标内容为空'
                continue
            }

            $canvasSize = 256
            $ratio = [Math]::Min($canvasSize / $bitmap.Width, $canvasSize / $bitmap.Height)
            $drawWidth = [int][Math]::Max(1, [Math]::Round($bitmap.Width * $ratio))
            $drawHeight = [int][Math]::Max(1, [Math]::Round($bitmap.Height * $ratio))
            $offsetX = [int][Math]::Floor(($canvasSize - $drawWidth) / 2)
            $offsetY = [int][Math]::Floor(($canvasSize - $drawHeight) / 2)

            $canvas = New-Object System.Drawing.Bitmap($canvasSize, $canvasSize)
            try {
                $graphics = [System.Drawing.Graphics]::FromImage($canvas)
                try {
                    $graphics.Clear([System.Drawing.Color]::Transparent)
                    $graphics.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
                    $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
                    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
                    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
                    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
                    $graphics.DrawImage($bitmap, $offsetX, $offsetY, $drawWidth, $drawHeight)
                } finally {
                    $graphics.Dispose()
                }
                $canvas.Save($dest, [System.Drawing.Imaging.ImageFormat]::Png)
            } finally {
                $canvas.Dispose()
                $bitmap.Dispose()
            }

            if ((Test-Path -LiteralPath $dest -PathType Leaf) -and (Get-Item -LiteralPath $dest).Length -gt 64) {
                $ok = $true
                $reason = ''
            } else {
                $reason = '写入图标文件失败'
            }
        } catch {
            $reason = $_.Exception.Message
        }
    }

    $results += [PSCustomObject]@{ id = [string]$task.id; ok = $ok; reason = $reason }
}

$results | ConvertTo-Json -Compress -Depth 3 | Set-Content -LiteralPath $OutputFile -Encoding UTF8
