@echo off
ECHO Attivazione dell'ambiente virtuale e installazione dei pacchetti...
CALL venv\Scripts\activate.bat
pip install -r requirements.txt

REM ECHO Initializing database...
REM python init_db.py

ECHO Starting Flask application...
ECHO Premi CTRL+C per fermare il server.
python app.py
