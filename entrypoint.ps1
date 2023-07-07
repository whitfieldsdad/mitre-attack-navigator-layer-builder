make requirements

if (Test-Path venv) {
  Write-Host "venv directory exists"
}
else {
  Write-Host "venv directory does not exist"
  python3 -m venv venv
  Write-Host "venv directory created"
}

# Activate venv
Write-Host "Activating venv"
venv\Scripts\Activate.ps1

# Install dependencies
Write-Host "Installing dependencies"
python3 -m pip install -r requirements.txt

# Run the script
Write-Host "Running script"
python3 -m mitre_attack_navigator_builder.cli $@

# Deactivate venv
Write-Host "Deactivating venv"
deactivate
