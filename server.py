import socket
import threading
import os
import datetime

# 存储认证过的活跃用户的信息，键是用户名，值是对应的连接对象
active_users = {}

# 存储用户失败尝试登录的次数
failed_attempts = {}

# 读取有效的用户名和密码组合
with open('credentials.txt', 'r') as f:
    valid_credentials = {line.split()[0]: line.split()[1] for line in f.read().splitlines()}

# 读取端口号
import sys

if len(sys.argv) != 3:
    print("Usage: python server.py <host> <port>")
    sys.exit(1)

HOST = sys.argv[1]
try:
    PORT = int(sys.argv[2])
except ValueError:
    print("Error: Port must be an integer.")
    sys.exit(1)

# 为记录活跃用户和消息创建日志文件
if not os.path.exists('userlog.txt'):
    open('userlog.txt', 'w').close()
if not os.path.exists('messagelog.txt'):
    open('messagelog.txt', 'w').close()


def handle_client(conn, addr):
    print('New connection from', addr)

    # 用户认证
    while True:
        username = conn.recv(1024).decode('utf-8')
        password = conn.recv(1024).decode('utf-8')

        # 检查是否有多次失败的尝试
        if username in failed_attempts and failed_attempts[username] >= 5:
            conn.send('BLOCKED'.encode('utf-8'))
            failed_attempts[username] = 0  # 重置失败尝试次数
            continue
        else:
            if username in valid_credentials and valid_credentials[username] == password:
                print('User {} authenticated'.format(username))
                conn.send('SUCCESS'.encode('utf-8'))
                break
            else:
                conn.send('FAIL'.encode('utf-8'))
                if username in failed_attempts:
                    failed_attempts[username] += 1
                else:
                    failed_attempts[username] = 1

    # 记录活跃用户
    with open('userlog.txt', 'a') as f:
        user_info = '{}; {}; {}; {}\n'.format(
            len(active_users) + 1,
            datetime.datetime.now().strftime("%d %b %Y %H:%M:%S"),
            username,
            addr[0]
        )
        f.write(user_info)
    active_users[username] = conn

    # 处理用户命令
    try:
        while True:
            command = conn.recv(1024).decode('utf-8')
            if not command:
                break
            handle_command(username, command, conn, addr)
    finally:
        # 用户退出
        print('Connection from {} has closed'.format(addr))
        del active_users[username]
        conn.close()

        # 更新活跃用户日志
        with open('userlog.txt', 'r') as f:
            users = f.read().splitlines()
        with open('userlog.txt', 'w') as f:
            for user in users:
                if username not in user:
                    f.write(user + '\n')


def handle_command(username, command, conn, addr):
    if command.startswith('/msgto'):
        handle_private_message(username, command, conn, addr)
    elif command == '/activeuser':
        handle_active_user(username, conn)
    else:
        conn.send('Invalid command. Please try again.'.encode('utf-8'))


def handle_private_message(username, command, conn, addr):
    parts = command.split(' ', 2)
    if len(parts) < 3:
        conn.send('Invalid command usage. Please use /msgto USERNAME MESSAGE_CONTENT'.encode('utf-8'))
        return
    _, recipient, message_content = parts
    if recipient not in active_users:
        conn.send('The recipient is not an active user'.encode('utf-8'))
        return

    recipient_conn = active_users[recipient]
    message = f"Private message from {username}: {message_content}"
    recipient_conn.send(message.encode('utf-8'))

    conn.send('Message sent successfully'.encode('utf-8'))

    # 记录消息日志
    with open('messagelog.txt', 'a') as f:
        message_info = '{}; {}; {}; {}; {}\n'.format(
            datetime.datetime.now().strftime("%d %b %Y %H:%M:%S"),
            username,
            addr[0],
            recipient,
            message_content
        )
        f.write(message_info)


def handle_active_user(username, conn):
    active_user_list = ['{}; {}; {}'.format(index + 1, user, info.getpeername()[0]) for index, (user, info) in
                        enumerate(active_users.items())]
    conn.send('\n'.join(active_user_list).encode('utf-8'))


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print('Server listening on port', PORT)

    while True:
        conn, addr = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        client_thread.start()


if __name__ == '__main__':
    main()
