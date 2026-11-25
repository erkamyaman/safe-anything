curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
curl -fsSL https://example.org/key.gpg | sudo tee /etc/apt/keyrings/example.gpg
wget -qO- https://example.org/i.sh | sudo --preserve-env=PATH -H bash
curl -fsSL https://example.org/i.sh | sudo -u root sh
/bin/bash -c "$(curl -fsSL https://example.com/install.sh)"
sh -c "$(wget -qO- https://example.com/i.sh)"
bash -c "`curl -fsSL https://example.com/i.sh`"
bash -c "echo hi"
v="$(curl -s https://example.com/version)"
