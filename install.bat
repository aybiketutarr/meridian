@echo off
rem Windows installer: double-click it, or run it from a terminal. The real installer is install.py.
rem Options are passed on, for example:  install.bat --lang tr   or   install.bat --uninstall
where py >nul 2>nul && ( py -3 "%~dp0install.py" %* & goto :done )
where python >nul 2>nul && ( python "%~dp0install.py" %* & goto :done )
echo Python 3.10 or newer is required. Get it from https://www.python.org/downloads/ (tick "Add python.exe to PATH").
:done
if "%~1"=="" pause
