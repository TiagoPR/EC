
# Server
async def handle_echo(reader, writer):
    print("OLAAAA")
    data = await reader.read(100)
    message = data.decode()

    addr = writer.get_extra_info('peername')

    print(f"Received {message} from {addr}")

    recebido = receiver(key, nonce, associateddata, message)

    print(f"Send: {recebido}")
    writer.write(data)
    await writer.drain()

    print("Closing the connection")
    writer.close()

async def main():
    print("oiiiii")
    server = await asyncio.start_server(
        handle_echo, '127.0.0.1', 8888)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()
