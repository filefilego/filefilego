# Development & Technical Requirements

### Channel Nodes

#### Constrains
The following constraints apply to each node type:
1. Channel: `Size`, `ParentHash`, `ContentType` are not needed
2. `FILE, DIR, SUBCHANNEL, ENTRY` require correct  `ParentHash` and correct Permissions
3. `SUBCHANNEL` have OPTIONAL `Size` 

Permissions are as follows:
1. `Owner` has full access
2. `Admins` memebers can create everything except changing the `Owner` property of a node
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

### Boltdb Design

We decide to use a set of buckets to organize the data within the boltdb file. We have the following buckets:
1. `mempool` used for storing pool data
2. `blocks` blocks are linked with each other within this bucket
3. `accounts` hold the metadata of each address
4. `channels` is used as an index to get a list of channels without scanning all the blockchain
5. `nodes` channel nodes are saved in this bucket
6. `node_nodes` represents the relationships between nodes. Since boltdb keys are sorted (indexed) we utilize this feature to have keys of type: `ParentHash+Hash` so we can have fater lookups.


### Binlayer

#### Binlayer database index

Binary metadata location and hashes are stored within a boltdb database which is offchain. The only problem (we have already solved) with this approach is that when a binlayer operator moves the data from one node to another, they must make sure to copy this database file too. However we can still extract the structure from the filesystem itself, using the actual filesystem names which represent the onchain node hash, and by hashing the content of the file we get the rest of the information needed to restore the database.

### Protobuf

Protobuf related notes

#### Protoc compiler

Download and install using the following commands:

```
curl -OL https://github.com/protocolbuffers/protobuf/releases/download/v3.14.0/protoc-3.14.0-linux-x86_64.zip
unzip protoc-3.14.0-linux-x86_64.zip -d protoc3
sudo cp -r protoc3/bin/* /usr/local/bin/
sudo cp -r protoc3/include/* /usr/local/include/
sudo chown $USER /usr/local/bin/protoc
protoc
```

#### Protobuf message compilation for Golang

Installation:


```
go install google.golang.org/protobuf/cmd/protoc-gen-go
```

Compile to go:

```
protoc --go_out=. *.proto
```

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
docker run -it ffg --rpc --http --httpport=8090 --httpaddr=0.0.0.0 --bootstrapnodes="/ip4/192.168.0.10/tcp/10209/p2p/16Uiu2HAmKR42X3hxnRBQnKCGB9VfAfbg54ajhFA9MDvJtesBxrYS" --rpcservices="channel,transaction,account,block,ffg"
```


### Docker-compose Simulation

Using docker-compose we setup 2 full nodes and 1 verifier which connect to the host running an instance of filefilego cli.

```
docker-compose up   // starts the containers
docker-compose down // kills everything
```

to see logs of a specific container:

```
docker-compose logs -f node1
```
