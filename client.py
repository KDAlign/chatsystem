import socket
import threading
import sys

if len(sys.argv) != 4:
    print("Usage: python client.py <server_ip> <server_port> <client_port>")
    sys.exit(1)

server_ip = sys.argv[1]
try:
    server_port = int(sys.argv[2])
    client_port = int(sys.argv[3])
except ValueError:
    print("Error: Ports must be integers.")
    sys.exit(1)


def receive_messages(sock):
    while True:
        message = sock.recv(1024).decode('utf-8')
        if not message:
            break
        print(message)


def send_messages(sock):
    while True:
        message = input()
        sock.send(message.encode('utf-8'))
        if message.startswith('/exit'):
            break


def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((server_ip, server_port))
    except Exception as e:
        print("Could not connect to server:", e)
        sys.exit(1)

    print("Connected to server at {}:{}.".format(server_ip, server_port))

    # 用户认证
    while True:
        username = input("Enter username: ")
        password = input("Enter password: ")

        client_socket.send(username.encode('utf-8'))
        client_socket.send(password.encode('utf-8'))

        response = client_socket.recv(1024).decode('utf-8')
        if response == 'SUCCESS':
            print("Authentication successful")
            break
        elif response == 'BLOCKED':
            print("Too many failed attempts. Try again later.")
        elif response == 'FAIL':
            print("Authentication failed. Try again.")
        else:
            print("Unknown response from server:", response)

    # 启动接收和发送消息的线程
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.start()

    send_thread = threading.Thread(target=send_messages, args=(client_socket,))
    send_thread.start()

    # 等待发送线程结束
    send_thread.join()
    print("Goodbye!")

    # 关闭客户端套接字
    client_socket.close()
    sys.exit(0)


if __name__ == "__main__":
    main()
