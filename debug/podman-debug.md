# Отладка окружения в podman

Создание контейнера в фоне

```bash
podman network create --ipv6 warp-pipe-network
podman run -d --name ubuntu-warp-pipe-proxy -p 2222:22 --systemd=always --network=warp-pipe-network --cap-add=NET_ADMIN --security-opt=unmask=/proc/sys/net -p 0.0.0.0:1081:1081/tcp -p 0.0.0.0:10443:10443/tcp ubuntu:latest bash -c "export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install -y --no-install-recommends openssh-server && mkdir -p /var/run/sshd && echo 'root:password' | chpasswd && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && systemctl enable ssh && exec /lib/systemd/systemd"
```

Копирование установщика в контейнер

```bash
scp -P 2222 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -r warp-pipe-proxy/ root@localhost:/tmp/
```

Подключение к контейнеру через ssh

```bash
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@localhost -p 2222
```