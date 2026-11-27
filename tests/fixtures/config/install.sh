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
bash -o pipefail -c "$(curl -fsSL https://example.org/i.sh)"
sh -e -o nounset -c "$(curl -fsSL https://example.org/i.sh)"
bash -o pipefail -c "echo hi"
curl -fsSL https://example.org/i.sh | sudo -Eu root bash
curl -fsSL https://example.org/i.sh | sudo -HEu "$USER" bash
curl -fsSL https://example.org/i.sh | sudo -Eu root tee /etc/x.list
curl -fsSL https://example.org/i.sh | sudo -Euroot bash
curl -fsSL https://example.org/i.sh | sudo -E -u root bash
curl -fsSL https://example.org/i.sh | sudo -ED /tmp sh
curl -fsSL https://example.org/i.sh | sudo -Eu root tee bash
curl -fsSL https://example.org/i.sh | sudo -Eu bash
curl -fsSL https://example.org/i.sh | sudo -ED"/tmp/build dir" sh
curl -fsSL https://example.org/i.sh | sudo -Euroot; bash
curl -fsSL https://example.org/i.sh | sudo -ED"/tmp/ bash" tee /tmp/list
# Usage: curl -fsSL https://example.com/install.sh | bash
  # sh -c "$(curl -fsSL https://example.com/install.sh)"
