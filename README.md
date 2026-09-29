# CodeAccessX Network Agent

Agente local para Windows + LM Studio.

## 1. Requisitos

- Windows 10/11
- Python 3.11+
- LM Studio com um modelo carregado
- API local do LM Studio habilitada

## 2. Instalação

Abra PowerShell:

```powershell
cd C:\CodeAccessX\NetworkAgent
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Se o PowerShell bloquear a ativação, execute:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

e ative novamente.

## 3. LM Studio

Inicie o LM Studio, carregue um modelo e habilite o servidor local compatível com OpenAI.
Por padrão este projeto espera:

http://127.0.0.1:1234/v1

Se a porta for diferente, altere `lm_studio.base_url` no `config.json`.

## 4. Executar

```powershell
python agent.py
```

API:

http://127.0.0.1:8765/docs

## 5. Testar

```powershell
Invoke-RestMethod http://127.0.0.1:8765/health
Invoke-RestMethod http://127.0.0.1:8765/devices
Invoke-RestMethod -Method Post http://127.0.0.1:8765/scan
```

Consulta ao LM Studio:

```powershell
$body = @{ message = "Quantos dispositivos estão online?" } | ConvertTo-Json
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8765/lmstudio/chat `
  -ContentType "application/json" `
  -Body $body
```

## 6. Segurança

Por padrão a API escuta somente em `127.0.0.1`, portanto não fica exposta para a LAN.

Para usar uma API key, configure:

```json
"security": {
  "allow_lan_api": false,
  "api_key": "uma-chave-forte"
}
```

Depois envie o header:

```text
X-API-Key: uma-chave-forte
```

O agente usa apenas descoberta básica por ICMP/ARP/DNS. Ele não faz exploração de portas, tentativa de autenticação ou execução remota.
