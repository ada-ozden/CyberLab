import socket
import logging

HOST = "0.0.0.0"
PORT = 2222


logging.basicConfig(
    filename="/app/logs/honeypot.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)


def start_honeypot():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen(5)

    print(f"Honeypot listening on {HOST}:{PORT}")

    while True:
        client, address = server.accept()

        client_ip, client_port = address

        logging.info(
            f"CONNECTION | source_ip={client_ip} "
            f"source_port={client_port}"
        )

        print(
            f"Connection from {client_ip}:{client_port}"
        )

        try:
            client.settimeout(5)

            data = client.recv(1024)

            if data:
                message = data.decode(
                    "utf-8",
                    errors="replace"
                )

                logging.info(
                    f"DATA | source_ip={client_ip} "
                    f"data={message!r}"
                )

        except socket.timeout:
            logging.info(
                f"TIMEOUT | source_ip={client_ip}"
            )

        finally:
            client.close()


if __name__ == "__main__":
    start_honeypot()