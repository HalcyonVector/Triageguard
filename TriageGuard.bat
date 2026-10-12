@echo off
rem Double-click to start the TriageGuard dashboard. First run sets everything up.
cd /d "%~dp0"
set PY=.venv\Scripts\python.exe

if not exist "%PY%" (
  echo First run: creating the Python environment in .venv ...
  py -3 -m venv .venv 2>/dev/null || python -m venv .venv
)
"%PY%" -c "import volatility3, pefile, pyshark" 2>/dev/null || (
  echo Installing the required packages, this happens once ...
  "%PY%" -m pip install -r requirements.txt
)

where git >/dev/null 2>/dev/null && git pull --ff-only

rem Optional: put GROQ_API_KEY=... in a file called .env here for the LLM reports
"%PY%" -m triageguard dashboard
pause
