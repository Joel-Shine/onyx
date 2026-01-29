# server.py
# Install requirements: pip install fastapi uvicorn websockets

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

app = FastAPI()

# Store active rooms: { "room_id": [socket1, socket2] }
rooms = {}

@app.websocket("/ws/{room_id}")
async def websocket_endpoint(websocket: WebSocket, room_id: str):
    await websocket.accept()
    
    # Create room if it doesn't exist
    if room_id not in rooms:
        rooms[room_id] = []
    
    # Security: Max 2 people per room
    if len(rooms[room_id]) >= 2:
        await websocket.close(code=4000, reason="Room is full")
        return

    # Add user to the room
    rooms[room_id].append(websocket)
    me = websocket
    print(f"User joined room: {room_id}")

    # --- THE SYNCHRONIZATION LOGIC ---
    # If the room is now full (2 people), tell everyone to START.
    if len(rooms[room_id]) == 2:
        print(f"Room {room_id} is full! Starting handshake...")
        for connection in rooms[room_id]:
            await connection.send_bytes(b"READY")
    # ---------------------------------

    try:
        # The Relay Loop: Whatever I get, I send to the other person
        while True:
            data = await me.receive_bytes()
            
            # Find the partner
            peers = rooms[room_id]
            for peer in peers:
                if peer != me:
                    await peer.send_bytes(data)
                    
    except WebSocketDisconnect:
        # Cleanup
        if room_id in rooms and me in rooms[room_id]:
            rooms[room_id].remove(me)
            if not rooms[room_id]:
                del rooms[room_id]
        print(f"User left room: {room_id}")