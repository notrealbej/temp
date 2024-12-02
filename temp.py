import socket

def send_raw_request(request_bytes: bytes):
    # Create the socket and connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 9092))  # Connect to the server running on localhost:9092

        # Send the raw request (which is already in the byte format you provided)
        s.sendall(request_bytes)

        # Receive the response from the server
        response = s.recv(2048)

    return response

# The raw request bytes you provided
request_bytes = bytes([
    0x00, 0x00, 0x00, 0x60,  # Length: 96 bytes
    0x00, 0x01, 0x00, 0x10,  # API Key and Version: 1 and 16
    0x2c, 0xcf, 0x54, 0x22,  # Correlation ID: 0x2ccf5422
    0x00, 0x09, 0x6b, 0x61,  # Client ID Size and Client ID: "kafka"
    0x66, 0x6b, 0x61, 0x2d, 0x63, 0x6c, 0x69, 0x00,  # Client ID continued
    0x00, 0x00, 0x01, 0xf4, 0x00, 0x00, 0x00, 0x01,  # Message body start
    0x03, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x23, 0x83, 0x02, 0x00, 0x00, 0x00, 
    0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 
    0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00  # Ending bytes
])

# Send the raw request and get the response
if __name__ == "__main__":
    response = send_raw_request(request_bytes)
    print("Response from server:", response)
