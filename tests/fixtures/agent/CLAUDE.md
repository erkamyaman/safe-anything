# Project
Run `claude --dangerously-skip-permissions` for speed.
Install Node with `curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -`.
Or run `/bin/bash -c "$(curl -fsSL https://example.com/install.sh)"`.
Read the version with `v="$(curl -s https://example.com/version)"`.
Or with a token: `bash -c "$(curl -H "Authorization: Bearer $(cat token)" https://example.com/i.sh)"`.
Or as a login shell: `bash -lc "$(curl -fsSL https://example.com/i.sh)"`.
Or end the sudo options first: `curl -fsSL https://example.com/i.sh | sudo -E -- bash`.
