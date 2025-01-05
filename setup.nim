# setup.nim
import os, strformat, parseopt, strutils

var projectName = ""

var p = initOptParser(commandLineParams())
while true:
  p.next()
  case p.kind
  of cmdEnd: break
  of cmdArgument:
    if projectName == "":
      projectName = p.key
    else:
      echo "Error: Multiple project names provided"
      quit(1)
  of cmdLongOption, cmdShortOption:
    case p.key
    of "help", "h":
      echo """
Usage: nim c -r setup.nim [project_name]

Arguments:
  project_name    Name of the project to create

Options:
  -h, --help     Show this help message
"""
      quit(0)
    else:
      echo "Unknown option: ", p.key
      quit(1)

if projectName == "":
  echo "Error: Project name is required"
  echo "Usage: nim c -r setup.nim [project_name]"
  quit(1)

const Directories = [
  "",
  "src",
  "src/server",
  "src/models",
  "src/services",
  "src/utils",
  "tests",
  "config"
]

proc createProjectDir(projectName, dir: string) =
  let path = if dir.len > 0: projectName / dir else: projectName
  if not dirExists(path):
    echo fmt"Creating directory: {path}"
    createDir(path)

proc createProjectFile(path, content: string) =
  echo fmt"Creating file: {path}"
  writeFile(path, content.strip())

proc setupProject(name: string) =
  echo fmt"Setting up project: {name}"
  
  for dir in Directories:
    createProjectDir(name, dir)
  
  # Create .nimble file
  let nimbleContent = fmt"""
version       = "0.1.0"
author        = "Your Name"
description   = "Real-time check-in server"
license       = "MIT"
srcDir        = "src"
bin           = @["{name}"]

requires "nim >= 1.6.0"
requires "checksums"
"""
  createProjectFile(name / fmt"{name}.nimble", nimbleContent)
  # ... (continuation of setupProject proc)

  # Create config.nims
  let configNimsContent = """
switch("threads", "on")
switch("gc", "arc")
switch("define", "ssl")
"""
  createProjectFile(name / "config" / "config.nims", configNimsContent)
  
  # Create src/config.nim
  let configContent = """
type
  ServerConfig* = object
    port*: int
    maxClients*: int
    cleanupInterval*: int

proc loadConfig*(): ServerConfig =
  ServerConfig(
    port: 8080,
    maxClients: 1000,
    cleanupInterval: 300
  )
"""
  createProjectFile(name / "src" / "config.nim", configContent)

  # Create src/types.nim
  let typesContent = """
import std/[asyncnet, times, hashes, json]

type
  ClientID* = distinct string

  Location* = object
    latitude*: float
    longitude*: float
    timestamp*: DateTime

  Client* = ref object
    id*: ClientID
    socket*: AsyncSocket
    lastSeen*: DateTime

proc hash*(x: ClientID): Hash =
  hash(string(x))

proc `$`*(x: ClientID): string =
  string(x)

proc `==`*(a, b: ClientID): bool {.borrow.}
proc `<`*(a, b: ClientID): bool {.borrow.}
proc `<=`*(a, b: ClientID): bool {.borrow.}

# JSON serialization
proc `%`*(id: ClientID): JsonNode =
  % string(id)

proc `%`*(loc: Location): JsonNode =
  %*{
    "latitude": loc.latitude,
    "longitude": loc.longitude,
    "timestamp": loc.timestamp.format("yyyy-MM-dd'T'HH:mm:ss'Z'")
  }

proc `%`*(data: tuple[id: ClientID, loc: Location]): JsonNode =
  %*{
    "id": data.id,
    "location": data.loc
  }
"""
  createProjectFile(name / "src" / "types.nim", typesContent)
  # ... (continuation of setupProject proc)

  # Create src/server/websocket.nim
  let websocketContent = """
import std/[asyncnet, asyncdispatch, endians]

const
  PAYLOAD_LEN_SHORT = 125
  PAYLOAD_LEN_MEDIUM = 126
  PAYLOAD_LEN_LARGE = 127
  OPCODE_TEXT = 0x1
  OPCODE_BINARY = 0x2
  OPCODE_CLOSE = 0x8
  OPCODE_PING = 0x9
  OPCODE_PONG = 0xA

type
  WebSocketFrame* = object
    fin*: bool
    rsv1*, rsv2*, rsv3*: bool
    opcode*: uint8
    mask*: bool
    payload*: string

proc decodeFrame*(client: AsyncSocket): Future[WebSocketFrame] {.async.} =
  var frame: WebSocketFrame
  var header = await client.recv(2)
  if header.len != 2:
    raise newException(IOError, "Connection closed")

  let byte1 = header[0].uint8
  frame.fin = (byte1 and 0x80) != 0
  frame.rsv1 = (byte1 and 0x40) != 0
  frame.rsv2 = (byte1 and 0x20) != 0
  frame.rsv3 = (byte1 and 0x10) != 0
  frame.opcode = byte1 and 0x0F

  let byte2 = header[1].uint8
  frame.mask = (byte2 and 0x80) != 0
  var payloadLen = byte2 and 0x7F

  var extendedLen: uint64 = 0
  if payloadLen == PAYLOAD_LEN_MEDIUM:
    var lenBytes = await client.recv(2)
    extendedLen = uint16(lenBytes[0]) shl 8 or uint16(lenBytes[1])
    payloadLen = uint8(extendedLen)
  elif payloadLen == PAYLOAD_LEN_LARGE:
    var lenBytes = await client.recv(8)
    for i in 0..7:
      extendedLen = extendedLen shl 8 or uint64(lenBytes[i])
    payloadLen = uint8(extendedLen)

  var maskingKey = if frame.mask: await client.recv(4)
                   else: ""

  if payloadLen > 0:
    var payload = await client.recv(int(payloadLen))
    if frame.mask and payload.len > 0:
      for i in 0..<payload.len:
        payload[i] = char(uint8(payload[i]) xor uint8(maskingKey[i mod 4]))
    frame.payload = payload

  result = frame

proc encodeFrame*(data: string, opcode: uint8 = OPCODE_TEXT): string =
  let length = data.len
  var header: seq[byte] = @[byte(0x80 or opcode)]
  
  if length <= PAYLOAD_LEN_SHORT:
    header.add(byte(length))
  elif length <= 65535:
    header.add(byte(PAYLOAD_LEN_MEDIUM))
    header.add(byte((length shr 8) and 0xFF))
    header.add(byte(length and 0xFF))
  else:
    header.add(byte(PAYLOAD_LEN_LARGE))
    for i in countdown(7, 0):
      header.add(byte((length shr (i * 8)) and 0xFF))

  result = cast[string](header) & data
"""
  createProjectFile(name / "src" / "server" / "websocket.nim", websocketContent)

  # Create src/server/connection.nim
  let connectionContent = """
import std/[asyncnet, asyncdispatch, json, times, strutils, base64]
import checksums/sha1
import websocket
import ../types
import ../services/[storage, broadcast]

proc readHttpHeaders(client: AsyncSocket): Future[seq[string]] {.async.} =
  var headers: seq[string] = @[]
  while true:
    let line = await client.recvLine()
    if line == "\\r\\n" or line == "": break
    headers.add(line)
  return headers

proc processHandshake(headers: seq[string]): tuple[isWebSocket: bool, response: string] =
  var 
    isWebSocket = false
    key = ""
    
  for header in headers:
    if header.startsWith("Sec-WebSocket-Key:"):
      isWebSocket = true
      key = header.split(": ")[1].strip()
      break

  if isWebSocket:
    let concat = key.strip() & "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    let acceptKey = base64.encode($secureHash(concat))
    
    result = (true, "HTTP/1.1 101 Switching Protocols\\r\\n" &
                    "Upgrade: websocket\\r\\n" &
                    "Connection: Upgrade\\r\\n" &
                    "Sec-WebSocket-Accept: " & acceptKey & "\\r\\n\\r\\n")
  elif headers[0].contains("GET /healthz"):
    result = (false, "HTTP/1.1 200 OK\\r\\n" &
                    "Content-Type: application/json\\r\\n" &
                    "Content-Length: 15\\r\\n\\r\\n" &
                    "{\"status\":\"ok\"}")
  else:
    result = (false, "HTTP/1.1 404 Not Found\\r\\n" &
                    "Content-Type: application/json\\r\\n" &
                    "Content-Length: 25\\r\\n\\r\\n" &
                    "{\"status\":\"not found\"}")

proc handleClient*(client: Client, storage: StorageService, broadcast: BroadcastService) {.async.} =
  try:
    let headers = await readHttpHeaders(client.socket)
    if headers.len == 0: return
    
    let (isWebSocket, response) = processHandshake(headers)
    await client.socket.send(response)
    
    if not isWebSocket:
      client.socket.close()
      return

    # Handle WebSocket connection
    while true:
      try:
        let frame = await decodeFrame(client.socket)
        
        case frame.opcode
        of OPCODE_CLOSE:
          break
        of OPCODE_TEXT:
          let data = parseJson(frame.payload)
          let location = Location(
            latitude: data["latitude"].getFloat,
            longitude: data["longitude"].getFloat,
            timestamp: now()
          )
          
          storage.updateLocation(client.id, location)
          await broadcast.broadcastLocations()
        of OPCODE_PING:
          await client.socket.send(encodeFrame(frame.payload, OPCODE_PONG))
        else:
          discard
          
      except JsonParsingError:
        echo "Invalid JSON received"
      except KeyError:
        echo "Invalid location format"
      except:
        break
        
  finally:
    storage.removeClient(client.id)
    client.socket.close()
"""
  createProjectFile(name / "src" / "server" / "connection.nim", connectionContent)
  # ... (continuation of setupProject proc)

  # Create src/services/storage.nim
  let storageContent = """
import std/tables
import ../types

type StorageService* = ref object
  clients*: TableRef[ClientID, Client]
  locations*: TableRef[ClientID, Location]

proc newStorageService*(): StorageService =
  StorageService(
    clients: newTable[ClientID, Client](),
    locations: newTable[ClientID, Location]()
  )

proc addClient*(s: StorageService, client: Client) =
  s.clients[client.id] = client

proc removeClient*(s: StorageService, id: ClientID) =
  s.clients.del(id)
  s.locations.del(id)

proc updateLocation*(s: StorageService, id: ClientID, loc: Location) =
  s.locations[id] = loc

proc getLocations*(s: StorageService): seq[tuple[id: ClientID, loc: Location]] =
  for id, loc in pairs(s.locations[]):
    result.add((id, loc))
"""
  createProjectFile(name / "src" / "services" / "storage.nim", storageContent)

  # Create src/services/broadcast.nim
  let broadcastContent = """
import std/[asyncdispatch, json, tables, asyncnet]
import ../types
import ../server/websocket
import storage

type BroadcastService* = ref object
  storage*: StorageService

proc newBroadcastService*(storage: StorageService): BroadcastService =
  BroadcastService(storage: storage)

proc broadcastLocations*(b: BroadcastService) {.async.} =
  let locations = b.storage.getLocations()
  let jsonData = $(%locations)
  let frame = encodeFrame(jsonData)
  var disconnectedClients: seq[ClientID] = @[]
  
  for id, client in pairs(b.storage.clients[]):
    try:
      await client.socket.send(frame)
    except:
      disconnectedClients.add(id)
  
  # Clean up disconnected clients
  for id in disconnectedClients:
    b.storage.removeClient(id)
"""
  createProjectFile(name / "src" / "services" / "broadcast.nim", broadcastContent)

  # Create main source file
  let mainContent = fmt"""
import std/[asyncnet, asyncdispatch, strformat, nativesockets, times]
import types
import config
import server/connection
import services/[storage, broadcast]

proc serve() {{.async.}} =
  let config = loadConfig()
  let storage = newStorageService()
  let broadcast = newBroadcastService(storage)
  
  var server = newAsyncSocket()
  server.setSockOpt(OptReuseAddr, true)
  server.bindAddr(Port(config.port))
  server.listen()
  
  echo fmt"Server listening on port {{config.port}}"
  
  while true:
    let sock = await server.accept()
    let client = Client(
      id: ClientID($int(sock.getFd())),
      socket: sock,
      lastSeen: now()
    )
    
    storage.addClient(client)
    asyncCheck handleClient(client, storage, broadcast)

when isMainModule:
  echo "Starting {name}..."
  asyncCheck serve()
  runForever()
"""
  createProjectFile(name / "src" / fmt"{name}.nim", mainContent)

  # Create test file
  let testContent = fmt"""
import unittest
import ../src/{name}
import ../src/types
import ../src/server/websocket

suite "{name} Tests":
  test "WebSocket frame encoding/decoding":
    let testData = "Hello, WebSocket!"
    let encoded = encodeFrame(testData)
    check encoded.len > testData.len # Should include frame headers
"""
  createProjectFile(name / "tests" / "test_server.nim", testContent)

  # Create README
  let readmeContent = fmt"""
# {name}

A real-time check-in server implemented in Nim.

## Setup

1. Install Nim (version 1.6.0 or higher)
2. Clone this repository
3. Run `nimble install` in the project directory

## Running

```bash
nimble run
```

## API

The server provides:

1. WebSocket endpoint (default port 8080)
   - Send location updates as JSON:
     ```json
     {{
       "latitude": 40.7128,
       "longitude": -74.0060
     }}
     ```

2. HTTP endpoints:
   - GET /healthz - Health check endpoint
     Returns: `{{"status": "ok"}}` with 200 status code

## Configuration

Server configuration in `src/config.nim`:
- port: Server port (default: 8080)
- maxClients: Maximum concurrent clients (default: 1000)
- cleanupInterval: Cleanup interval in seconds (default: 300)

## License

MIT
"""
  createProjectFile(name / "README.md", readmeContent)

  echo "\nProject setup complete!"
  echo fmt"""
Next steps:
1. cd {name}
2. nimble install
3. nimble run
"""

when isMainModule:
  setupProject(projectName)
