import socket
import threading

def fetch_message(api_key: int, api_version: int, req_body):
    min_version, max_version = 0, 16
    # throttle_time_ms = 0
    tag_buffer = b"\x00"
    session_id = 0
    responses = []

    # print(req_body)
    # return b""

    error_code = int.to_bytes(0, 2,byteorder="big", signed=True)
    if max_version < api_version or api_version < min_version: 
        error_code = int.to_bytes(35, 2, byteorder="big", signed=True)

    throttle_time_ms = int.to_bytes(0, 4,byteorder="big", signed=True)
    session_id = req_body["session_id"]
    req_topics = req_body["topics"]
    num_request = len(req_topics)
    responses = int.to_bytes(num_request + 1, 1)
    for topic in req_topics:
        responses += topic["topic_id"]
        req_partitons = topic["partitions"]
        num_partitions = len(req_topics)
        responses += int.to_bytes(num_partitions + 1, 1)
        # for partitions
        idx = 0
        for _ in range(1, num_partitions + 1):
            responses += int.to_bytes(idx, 4)  # partition_index
            responses += int(100).to_bytes(2)  # error code
            responses += int.to_bytes(0, 8)  # high_watermark
            responses += int.to_bytes(0, 8)  # last_stable_offset
            responses += int.to_bytes(0, 8)  # log_start_offset
            responses += int.to_bytes(0 + 1, 1)  # num_aborted_transactions
            responses += int.to_bytes(0, 4)  # preferred_read_replica
            responses += int.to_bytes(1, 1, signed=True)  # COMPACT_RECORDS
            responses += tag_buffer
        responses += tag_buffer
    responses += tag_buffer

    return throttle_time_ms + error_code + session_id + responses

def apiversion_message(correlation_id: int, api_key: int, api_version: int):
    min_version, max_version = 0, 4
    throttle_time_ms = 0
    tag_buffer = b"\x00"

    error_code = 0
    if max_version < api_version or api_version < min_version: 
        error_code = 35

    message = correlation_id.to_bytes(4, byteorder="big")
    message += error_code.to_bytes(2, byteorder="big") + int(3).to_bytes(1, byteorder="big") #3 indicates 2 api keys
    message += api_key.to_bytes(2, byteorder="big") + min_version.to_bytes(2, byteorder="big")
    message += max_version.to_bytes(2, byteorder="big") + tag_buffer
    message += (1).to_bytes(2, byteorder="big") + min_version.to_bytes(2, byteorder="big")
    message += (16).to_bytes(2, byteorder="big") + tag_buffer
    message += throttle_time_ms.to_bytes(4, byteorder="big") + tag_buffer

    return message



def create_message(req) -> bytes:
    # message = ""
    request_headers = req["headers"]
    request_body = req["body"]

    correlation_id = int.from_bytes(request_headers["correlation_id"], byteorder="big")
    api_key = int.from_bytes(request_headers["api_key"], byteorder="big")
    api_version = int.from_bytes(request_headers["api_version"], byteorder="big")
    message = b""
    if api_key == 1:
        message = correlation_id.to_bytes(4, byteorder="big") + b"\x00" + fetch_message(api_key, api_version, req_body=request_body)
    elif api_key == 18:
        message = apiversion_message(correlation_id, api_key, api_version)

    message_len = len(message).to_bytes(4, byteorder="big")
    return message_len + message

def parse_header(req: bytes):
    request_length = (req[0:4])
    request_api_key = req[4:6]
    request_api_version = req[6:8]
    correlation_id = req[8:12]
    client_id_size = req[12:14]
    offset = int.from_bytes(client_id_size,byteorder="big", signed=True)
    client_id = req[14 : 14 + offset] if offset != -1 else b"\x00"
    offset = 14 if offset == -1 else 14 + offset
    tag_buffer = req[offset : offset + 1]
    offset += 1
    return {
        "length": request_length,
        "api_key": request_api_key,
        "api_version": request_api_version,
        "correlation_id": correlation_id,
        "client_id_size": client_id_size,
        "client_id": client_id,
        "tag_buffer": tag_buffer,
        "offset": int.to_bytes(offset, byteorder="big", length=4)
    }

def parse_fetch_request_v16(body):
    max_wait = body[0:4]
    min_bytes = body[4:8]
    max_bytes = body[8:12]
    iso_level = body[12:13]
    session_id = body[13:17]
    session_epoch = body[17:21]
    num_topics = body[21:22]
    topics = []
    offset = 0
    for i in range(1, int.from_bytes(num_topics, byteorder="big", signed=True)):
        topic_id = body[22 + offset: 22 + 16 + offset]
        num_partitions = body[22+16+offset: 22+17+offset]
        partitions = []
        for j in range(1, int.from_bytes(num_partitions, byteorder="big", signed=True)):
            partition = body[22+17+offset: 22+21+offset]
            current_leader_epoch = body[22+21+offset: 22+25+offset]
            fetch_offset = body[22+25+offset: 22+33+offset]
            last_fetched_epoch = body[22+33+offset: 22+37+offset]
            log_start_offset = body[22+37+offset: 22+45+offset]
            partition_max_bytes = body[22+45+offset: 22+49+offset]
            tag_buffer = body[22+49+offset: 22+50+offset]
            partitions.append({
                "partition": partition,
                "current_leader_epoch": current_leader_epoch,
                "fetch_offset": fetch_offset,
                "last_fetched_epoch": last_fetched_epoch,
                "log_start_offset": log_start_offset,
                "partition_max_bytes": partition_max_bytes,
            })

            offset += 55
        topics.append({
            "topic_id": topic_id,
            "partitions": partitions
        })
        offset += 1
    
    num_forgotten_topics_data = body[22+offset: 23+offset]
    forgotten_topics_data = []
    for _ in range(1, int.from_bytes(num_forgotten_topics_data, byteorder="big",signed=True)):
        topic_id_ftd = body[23 + offset : 23 + offset + 16]
        num_partitions_ftd = body[23 + offset + 16 : 23 + offset + 17]
        partitions_ftd = []
        for _ in range(1, int.from_bytes(num_partitions_ftd, signed=True)):
            partition_ftd = body[23 + offset + 17 : 23 + offset + 21]
            partitions_ftd.append(partition_ftd)
            offset += 4
        forgotten_topics_data.append(
            {"topic_id": topic_id_ftd, "partitions": partitions_ftd}
        )
        offset += 1
    # TODO: Figure out how to parse varint
    rack_id_len = body[23 + offset : 24 + offset]

    return {
        "max_wait_ms": max_wait,
        "min_bytes": min_bytes,
        "max_bytes": max_bytes,
        "isolation_level": iso_level,
        "session_id": session_id,
        "session_epoch": session_epoch,
        "topics": topics
    }

    

def parse_request_body(api_key, api_version, body):
    if api_key == 1 and api_version == 16:
        return parse_fetch_request_v16(body)
    return b""


def parse_request(req: bytes) -> dict[str, int]:
    headers = parse_header(req)
    offset = headers["offset"]
    body = parse_request_body(
        int.from_bytes(headers["api_key"], byteorder="big"),
        int.from_bytes(headers["api_version"], byteorder="big"),
        req[int.from_bytes(offset, byteorder="big") :],
    )
    return {"headers": headers, "body": body}

def handler(client):
    while True:
        request = client.recv(2048)
        if not request:
            break

        request_data = parse_request(request)

        message = create_message(request_data)
        client.sendall(message)

    client.close()


def main() -> None:
    server = socket.create_server(("localhost", 9092), reuse_port=True)

    while True:
        client, _ = server.accept()
        threading.Thread(target=handler, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
