curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
curl -fsSL https://example.org/key.gpg | sudo tee /etc/apt/keyrings/example.gpg
wget -qO- https://example.org/i.sh | sudo --preserve-env=PATH -H bash
curl -fsSL https://example.org/i.sh | sudo -u root sh
/bin/bash -c "$(curl -fsSL https://example.com/install.sh)"
sh -c "$(wget -qO- https://example.com/i.sh)"
bash -c "`curl -fsSL https://example.com/i.sh`"
bash -c "echo hi"
v="$(curl -s https://example.com/version)"
curl -fsSL https://example.org/i.sh | sudo -u www-data bash
curl -fsSL https://example.org/i.sh | sudo --preserve-env=PATH,HOME bash
dash -c "$(wget -qO- https://example.com/i.sh)"
curl -fsSL https://example.org/k.gpg | sudo -u www-data tee /srv/k.gpg
curl -fsSL https://example.org/key.gpg | sudo -E tee bash
curl -fsSL https://example.org/i.sh | sudo -E --user root -H bash
curl -fsSL https://example.org/i.sh | sudo -u "$USER" bash
curl -fsSL https://example.org/i.sh | sudo -u python cat
curl -fsSL https://example.org/i.sh | sudo -D /tmp bash
bash -c "$(curl -H "Authorization: Bearer $(cat token)" https://example.org/i.sh)"
bash -lc "$(curl -fsSL https://example.com/i.sh)"
bash -e -c "$(curl -fsSL https://example.com/i.sh)"
curl -fsSL https://example.org/i.sh | sudo -E -- bash
