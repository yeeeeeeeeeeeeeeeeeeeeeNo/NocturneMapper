@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo Failed to initialize MSVC x64 environment
    exit /b 1
)

if not exist "%~dp0bin" mkdir "%~dp0bin"
if not exist "%~dp0obj" mkdir "%~dp0obj"

echo Compiling NocturneMapper.exe...
cl.exe /nologo /std:c++20 /O2 /EHsc /W3 /DUNICODE /D_UNICODE ^
    "%~dp0src\main.cpp" ^
    "%~dp0src\service_manager.cpp" ^
    "%~dp0src\carrier_io.cpp" ^
    "%~dp0src\pe_loader.cpp" ^
    "%~dp0src\telemetry_sanitizer.cpp" ^
    /Fo"%~dp0obj\\" ^
    /Fe"%~dp0bin\NocturneMapper.exe" ^
    /link Advapi32.lib Psapi.lib ntdll.lib
if errorlevel 1 exit /b 1

echo Compiling payload_sample.sys...
cl.exe /nologo /std:c++20 /O2 /GS- /Zl /c "%~dp0payload\payload_sample.cpp" /Fo"%~dp0obj\payload_sample.obj"
if errorlevel 1 exit /b 1

link.exe /nologo /DRIVER /SUBSYSTEM:NATIVE /NODEFAULTLIB /ENTRY:CustomDriverEntry /FIXED:NO ^
    "%~dp0obj\payload_sample.obj" /OUT:"%~dp0bin\payload_sample.sys"
if errorlevel 1 exit /b 1

echo Build succeeded:
echo   Mapper  : %~dp0bin\NocturneMapper.exe
echo   Payload : %~dp0bin\payload_sample.sys
endlocal
