@echo off

REM CD c:\pwic-path
IF "%1" == "start" (
	start /b python pwic.py --host 127.0.0.1 --port 8080
) ELSE IF "%1" == "stop" (
	python pwic_admin.py shutdown-server --port 8080 --force
) ELSE (
	python pwic_admin.py %*
)
