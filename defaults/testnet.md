# Iroha2 Testnet

[peer]: https://hyperledger-iroha.github.io/iroha-2-docs/reference/glossary.html#peer
[account]: https://hyperledger-iroha.github.io/iroha-2-docs/guide/configure/client-configuration.html#user-account
[assets]: https://hyperledger-iroha.github.io/iroha-2-docs/reference/glossary.html#asset
[transactions]: https://hyperledger-iroha.github.io/iroha-2-docs/blockchain/transactions.html#transactions
[query]: https://hyperledger-iroha.github.io/iroha-2-docs/reference/glossary.html#iroha-query

<!-- TODO abstract -->

## Generate your key pair and declare the public half

Run the utility tool on the docker image and get an unique key pair:

```bash
docker pull hyperledger/iroha:testnet-2.0.0-rc.1
docker run hyperledger/iroha:testnet-2.0.0-rc.1 kagami crypto
```

Example result:

```log
Public key (multihash): "ed0120CAA7C95F78150097932C3E1C62B89D73007C5F30D5907DD0FBE7EA09AF6658E2"
Private key (multihash): "8026205F4FD09D9F9C390B9E3B0DB7CFA3E8B8D567707227E549519CC0C170D87447B9"
```

Share the PUBLIC key with the administrator to register your [peer] and [account], and make sure to keep the PRIVATE key secret.

### Notes

* We use the same key pair for peer and account for convenience in testnet, but in general these key pairs are different
* Account is planned to be registration-free

## Launch your own peer

### Ensure static IP address

Verify that you have a white static IP address assigned to your machine or server. Usually in cloud provided by default.

### Configure port access

Open port `1337` on your firewall or add a corresponding rule in your cloud provider's security group settings to allow inbound traffic.

### Update docker compose configuration

Edit [docker-compose.volunteer.yml](./docker-compose.volunteer.yml) as follows:

```yml
# for the attached client
ACCOUNT_PUBLIC_KEY: <your_public_key>
ACCOUNT_PRIVATE_KEY: <your_private_key>
# for the peer
PUBLIC_KEY: <your_public_key>
PRIVATE_KEY: <your_private_key>
P2P_PUBLIC_ADDRESS: <your_advertised_host>:1337
```

### Start the docker container

Launch your Iroha peer by running the container:

```bash
docker compose -f docker-compose.volunteer.yml up -d
```

### Check peer status

Once your peer is registered, verify its status by running one of the following commands:

```bash
curl <your_host>:8080/status
curl <your_host>:8080/peers
```

* If peers are empty, it means your peer hasn't yet been registered or there're some network errors

## Make [transactions] via your peer

### Send and inspect a mock transaction

Attach a shell to the running container and run a transaction lister:

```docker
cd /config
iroha events transaction-pipeline
```

Attach another shell to the running container and send a mock transaction:

```docker
cd /config
cat transaction.mock.json | sed 's/extraordinary/astonishing/' | iroha json transaction
```

Example result:

```log
"50E8CE714D5207792BC819B9B118453E6E9F68B9B56515366F986B104B480103"
```

* If it claims the account is not found, your account may not be registered yet

Make sure that the transaction listener reports the transaction approval with the same hash:

```log
{
  "Pipeline": {
    "Transaction": {
      "hash": "50E8CE714D5207792BC819B9B118453E6E9F68B9B56515366F986B104B480103",
      "block_height": null,
      "status": "Queued"
    }
  }
}
{
  "Pipeline": {
    "Transaction": {
      "hash": "50E8CE714D5207792BC819B9B118453E6E9F68B9B56515366F986B104B480103",
      "block_height": 2,
      "status": "Approved"
    }
  }
}
```

[Query] the transaction details:

<!-- FIXME crates/iroha_cli/src/main.rs:1240:45

```docker
cd /config
cat query.transaction.json | sed 's/TRANSACTION_HASH/50E8CE714D5207792BC819B9B118453E6E9F68B9B56515366F986B104B480103/' | iroha json query
```
-->

<!-- TODO ### Transfer [assets]

You should have 100 roses as an airdrop. Query to check it:

```docker
cd /config
iroha asset get --id "rose##<your_public_key>@wonderland"
```

Example result:

```log
{
  "id": "rose##ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland",
  "value": {
    "Numeric": "100"
  }
}
```

Transfer some roses to your friend and check that your roses are decreased:

```docker
cd /config
iroha asset transfer --id "rose##<your_public_key>@wonderland" --to "<friend_public_key>@wonderland" --quantity 5
iroha asset get --id "rose##<your_public_key>@wonderland"
```

Example result:

```log
{
  "id": "rose##ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland",
  "value": {
    "Numeric": "95"
  }
}
```
-->

<!-- iroha asset list filter '{"Atom": {"Id": {"Account": {"Signatory": {"Atom": {"Equals": "<your_public_key>"}}}}}}' -->
