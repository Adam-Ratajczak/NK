Encryption:
- Data packet (MP)
- Compression (ZLIB)
- Encryption (libsodium, AES, XChaCha20-Poly1305)

Data packet:
MP data packet

Request:
Array of instructions
Object for each array element
Single key - command name
Object with multiple key-value pairs - command arguments

Response:
Array of responses, one for each instruction
Object for each array element
Single key - command name
Object with multiple key-value pairs - response data
Reserved response key: error : errorId;
Reserved response key: errorData : array of strings (in case error message needs to be formatted)

Commands:

