@echo off
rem Usage:  build.bat          - release build  -> build\dcc-csc.exe
rem         build.bat debug    - debug build with a console window for printf/std::cout
rem         build.bat run      - release build, then launch
rem Every .cpp file under src\ is compiled automatically.
setlocal EnableDelayedExpansion
set "ROOT=%~dp0"
set "TC=%ROOT%tools\w64devkit\bin"
if not exist "%TC%\g++.exe" (
    echo Toolchain not found. Run setup.bat first.
    exit /b 1
)
rem PATH change is local to this script only (setlocal).
set "PATH=%TC%;%PATH%"

cd /d "%ROOT%"
if not exist build mkdir build

set "FLAGS=-std=c++17 -O2 -mwindows -DNDEBUG"
if /i "%~1"=="debug" set "FLAGS=-std=c++17 -O0 -g -mconsole"

set "SRCS="
for /r src %%f in (*.cpp) do set SRCS=!SRCS! "%%f"

windres --include-dir res res\app.rc -O coff -o build\app.res || exit /b 1

g++ %FLAGS% -Wall -Wextra -Isrc -DUNICODE -D_UNICODE %SRCS% build\app.res -o build\dcc-csc.exe ^
    -static -lcomctl32 -lcomdlg32 -lgdi32 -luser32 -liphlpapi || exit /b 1

echo Built build\dcc-csc.exe
if /i "%~1"=="run" start "" build\dcc-csc.exe
