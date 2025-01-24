# testnet

1. Register a 1st volunteer peer (irohad9) by an admin account (ed0120..388E) whose client is attached to irohad0
2. Register a 2nd volunteer peer (irohad8) by an admin account (ed0120..388E) whose client is attached to irohad9

## How to reproduce

docker network create sharednet
cd defaults

docker compose -p c0 -f docker-compose.yml up -d
curl http://127.0.0.1:8083/status

docker compose -p c1 -f docker-compose.single.1.yml up -d
curl http://127.0.0.1:8079/status

<!-- 1. -->
(on irohad0) iroha -c config/client.toml peer register --key ed0120A36D508BDB1DBEFA4DF361F035A21DFD0F44C4DED67657537718DBF03C60E4C9
curl http://127.0.0.1:8079/status
curl http://127.0.0.1:8083/status

docker compose -p c2 -f docker-compose.single.2.yml up -d
curl http://127.0.0.1:8078/status

<!-- 2. -->
(on irohad9) iroha -c config/client.toml peer register --key ed0120EBAEC78474D37DD44FCC8E006A31FAD24352C2EF2B79361336B45922CDEA6A63
curl http://127.0.0.1:8078/status
curl http://127.0.0.1:8079/status
curl http://127.0.0.1:8083/status
