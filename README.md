# E2E-Signal-Protocol-encrypted-messaging
This repo runs on python 3.

Known issues are:
- No graceful way to exit server
- Must reset server every time clients disconnect, or issues may occur. Essentially, it's safer to start a new server every time a new test or session is made.
- users who have exited cannot re-enter the same session  


The python library pycryptodome is required to run this repo.
- pip install pycryptodome

To run the server: python3 chatServerDuplex.py

To run the client: python3 chatClientDuplex.py and follow the instructions (#join and #quit)

References used for report:
https://pycryptodome.readthedocs.io/en/latest/src/protocol/kdf.html

https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html

https://medium.com/@justinomora demystifying-the-signal-protocol-for-end-to-end-encryption-e2ee-ad6a567e6cb4
