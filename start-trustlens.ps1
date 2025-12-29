Write-Host "🚀 Starting TrustLens AI Security Platform..." -ForegroundColor Green
Write-Host ""
Write-Host "This will start the web server on http://localhost:3000" -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop the server when you're done" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press any key to continue..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host ""

npm run web