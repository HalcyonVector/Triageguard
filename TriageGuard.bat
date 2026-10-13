@echo off
rem Double-click to start the TriageGuard dashboard. First run sets everything up.
cd /d "%~dp0"
set PY=.venv\Scripts\python.exe

if not exist "%PY%" (
  echo First run: creating the Python environment in .venv ...
  py -3 -m venv .venv 2>nul || python -m venv .venv
)
"%PY%" -c "import volatility3, pefile, pyshark" 2>nul || (
  echo Installing the required packages, this happens once ...
  "%PY%" -m pip install -r requirements.txt
)

where git >nul 2>nul && (
  git pull --ff-only || (
    echo.
    echo Could not update the code. Usually a file was changed locally: run "git status" to see which.
    pause
  )
)

rem Optional: put GROQ_API_KEY=... in a file called .env here for the LLM reports
"%PY%" -m triageguard dashboard
pause
