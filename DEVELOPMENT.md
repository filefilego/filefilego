# Development & Technical Requirements

### Channel Nodes

#### Constraints
The following constraints apply to each node type:
1. Channel: `Size`, `ParentHash`, `ContentType` are not needed
2. `FILE, DIR, SUBCHANNEL, ENTRY` require correct  `ParentHash` and correct Permissions
3. `SUBCHANNEL` have OPTIONAL `Size` 

Permissions are as follows:
1. `Owner` has full access
2. `Admins` members can create everything except changing the `Owner` property of a node
3. `Posters` can create ONLY `Entries`, `DIR`, `FILE`
4. Guests are only allowed to create `OTHER` nodes, BUT with fees applied
5. Guests MAY act as Posters IF-AND-ONLY-IF, there is a wildcard`*` in the `Posters` field which simply means everyone can post.

Structure constraints:
1. `CHANNEL` can not be nested in any other types
2. `SUBCHANNEL` can be within a `CHANNEL` or `SUBCHANNEL` only
3. `ENTRY` can be within `CHANNEL` or `SUBCHANNEL`
4. `DIR and FILE` can be within only ENTRY
5. `OTHER` can be within an `ENTRY` ONLY

#### Visual Utilities

Filefilego aims to provide a user friendly interface with visual feedback including:
1. Logos/Favicons (Channel and Subchannel); The convention is to use a file named "ffg_favicon.png" to set the node's icon
2. Channel and Subchannel Cover photos; a file named "ffg_cover.png" to set the cover of the container node
3. Thumbnails for Entries which includes a limited number of gallery items; normal files(FILE) with attributes ("thumb=1"), ("gallery=1", "gallery=2" ... ) which means a thumbnail will be used and for the gallery 2 other images

Full nodes MUST NOT apply any download restrictions on these utilities. However there must be restrictions regarding file size to prevent abuse.


#### Protobuf message compilation for Javascript

```
cd filefilego
protoc --proto_path=node --js_out=import_style=commonjs,binary:build messages.proto
```

### Working with timestamps

to convert to time.Time:
```
ptypes.Timestamp(myMsg.Timestamp)
```

to get current timestamp:

```
ptypes.TimestampNow()
```

### Testing and Simulations

There is a docker file which creates an image with the current compiled cli. Just make sure to build the image using:
```
docker build . -t ffg
```

and then run a container using:

```
docker run -it ffg --node_identity_passphrase=admin --storage_token="admintoken" --addr=0.0.0.0 --http --http_addr=0.0.0.0 --bootstrap_nodes="/dns/host.docker.internal/tcp/10209/p2p/16Uiu2HAmScD2pAgjQxQLpfgod2bfZyajmJR4J9rfJ11jJq7w66LX"
```


### Docker-compose Simulation

Using docker-compose we setup 2 full nodes and 1 verifier which connect to the host running an instance of filefilego cli.

```
docker-compose up 
docker-compose down
```

to see logs of a specific container:

```
docker-compose logs -f node1
```
