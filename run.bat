@echo off
REM ==========================================================================
REM  AI Red Team Range launcher
REM
REM  Double click this file for a menu, or run a mode directly, for example:
REM      run.bat scan
REM      run.bat attack
REM      run.bat dashboard
REM  Modes: scan attack gate dashboard api tests integrations install
REM ==========================================================================
setlocal
pushd "%~dp0"

REM Direct mode: a mode name was passed as an argument
if not "%~1"=="" (
    call :run %~1
    popd
    endlocal
    exit /b
)

:menu
cls
echo ============================================
echo            AI Red Team Range
echo ============================================
echo   1. Quick scan            ^(mock, no API key^)
echo   2. Agentic attack demo   ^(mock^)
echo   3. CI gate check         ^(fail under 80^)
echo   4. Launch dashboard      ^(Streamlit^)
echo   5. Launch REST API       ^(FastAPI^)
echo   6. Run tests
echo   7. Integration status    ^(Garak / PyRIT^)
echo   8. Install / update dependencies
echo   0. Exit
echo ============================================
set "choice="
set /p choice=Choose an option:

if "%choice%"=="1" ( call :run scan         & goto after )
if "%choice%"=="2" ( call :run attack       & goto after )
if "%choice%"=="3" ( call :run gate         & goto after )
if "%choice%"=="4" ( call :run dashboard    & goto after )
if "%choice%"=="5" ( call :run api          & goto after )
if "%choice%"=="6" ( call :run tests        & goto after )
if "%choice%"=="7" ( call :run integrations & goto after )
if "%choice%"=="8" ( call :run install      & goto after )
if "%choice%"=="0" goto end
goto menu

:after
echo.
pause
goto menu

REM --------------------------------------------------------------------------
:run
if "%~1"=="scan"         python cli.py --target mock
if "%~1"=="attack"       python cli.py --target mock --goal leak-system-prompt
if "%~1"=="gate"         python cli.py --target mock --fail-under 80
if "%~1"=="dashboard"    python -m streamlit run app.py
if "%~1"=="api"          python -m uvicorn api:app --reload
if "%~1"=="tests"        python -m pytest tests/ -q
if "%~1"=="integrations" python cli.py --integrations
if "%~1"=="install"      pip install -r requirements.txt
goto :eof

:end
popd
endlocal
