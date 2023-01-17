# FileFileGo Decentralized Network

A Peer-to-peer data-sharing network with indexing/tracking, storage, full-text search, and incentive mechanism form a decentralized network that allows users to share data without a single point of failure and censorship. The architecture is designed in a way to prevent censorship and privacy issues, improves data availability with an incentive system based on game-theory concepts, and achieves fault-tolerance. To solve these challenges we propose a Peer-to-peer and decentralized data sharing network (FileFileGo) for the web3 era.

We have seen the rise of the Internet from the first days until now. Open internet suffers from big corporations and ISPs which censor freedom of speech. We have seen acts and statements such as SOPA, PIPA, ACTA and so many more from law-makers with the goal of controlling the Internet and the flow of information.

These days it's extremely difficult for sites like WikiLeaks, thepiratebay, and so on to operate without interruption and pressure from different oppressing parties. With these in mind, we have developed the FileFileGo protocol and stacks to allow users to access and share data without a single point of failure.

FileFileGo is not controlled by any individual. It's a joint effort by the Open-source community. The coin distribution is designed to be as fair as possible, with the emission of 15 FFG (the native currency) per block which is divided by 2 every 24 months.

FileFileGo is launched fairly - free of ICO/STO/IEO or pre-mine. We rely on a current PoA (Proof of Authority) consensus algorithm which will eventually be replaced by a PoS (Proof of Stake) to allow more parties to participate in the project. Support the movement by contributing to the project and develop innovative ideas that respect our digital rights, privacy, freedom of information, freedom from Internet censorship, and net neutrality.


# The Innovation: Proof of Transfer (PoX) / Proof of Data Possession (PoDP)

## Problem

Let us suppose that `node_1` needs to download some `data_x`, owned by `node_2`, and pay for the fees required by `node_2`. What happens in the case of Byzantine fault nodes? How do we verify successful data transfer to destination nodes and prevent the following malicious cases:
1. `node_1` is a dishonest node that reports `data_x` as invalid, to avoid paying the fees.
2. `node_2` is a dishonest node that serves `data_y` to `node_1` and claims that it's `data_x`.
## Solution


The network can resist Byzantine faults if `node_x` can broadcast (peer-to-peer) a value x, and satisfy the following:

1. If `node_x` is an honest node, then all honest nodes agree on the value x.
2. In any case, all honest nodes agree on the same value y.

Proof of Transfer solves exactly these problems. It is designed so that honest nodes within the network can verify and agree that `node_2` has successfully transferred `data_x` to `node_1`. In order to achieve this consensus mechanism, we introduce a set of verifiers which are responsible to challenge the participating nodes. A simple and straightforward approach would be to send the required data to a verifier and then forward it to the destination node. However, this approach introduces bandwidth and storage bottlenecks on the verifiers which in turn decreases the throughput of the overall network. The solution must have minimal bandwidth and storage/memory requirements.

```
              ┌───────────┐
     ┌────────►[verifiers]◄─────────┐
     │        └───────────┘         │
┌────┴───┐                     ┌────┴───┐
│        │                     │        │
│ node_1 ◄─────────────────────► node_2 │
│        │                     │        │
└────────┘                     ├────────┤
                               │ data_x │
                               └────────┘

```


#### Merkle Tree

Verifiers can use Merkle Trees as a data integrity verification mechanism without having access to the actual data. Participating nodes must generate Merkle trees which are used by verifiers for comparison and other operations.

```
     ABCD 
    /    \ 
   AB    CD 
  / \    / \ 
 A   B  C   D   
```

*ABCD*  is a merkle root. To prove the validity of *C*, for instance, all that's needed is *D*, so it can be proven that *C|D=CD*, *AB*, so it can be proven that *AB|CD=ABCD*.

#### The Algorithm

In this section, the complete life cycle of a data transfer verification is demonstrated.

1. **Data Discovery:** There are several wire protocols created to allow nodes to communicate with each other. The first protocol used by nodes is the `Data Query` protocol which allows nodes to broadcast queries to the network throughout a gossip channel and get the response back by using direct communication. Simply put, a node asks who hosts a specific piece of data.

```
             1. Data Query Request
                    ┌───────┐
    ┌───────────────►[nodes]├───────────────┐
    │               └───────┘               │
┌───┴────┐                             ┌────▼───┐
│        │                             │        │
│ node_1 │                             │ node_2 │
│        │                             │        │
└───▲────┘                             └───┬────┘
    │        2. Data Query Response        │
    └──────────────────────────────────────┘
```

2. **Smart Contract:** The `Data Query Response` payload contains all the information needed to prepare a smart contract transaction. This transaction is then broadcasted to the network which is then selected by a verifier.

```
┌──────────────────────────────────────┐
│              TRANSACTION             │
├──────────────────────────────────────┤
│  Data :                              │
│        - Data query response         │
│        - Remote node signature       │
│  Value:                              │
│        - Fees required by node       │
│                                      │
│  Fees :                              │
│        - Fees collected by verifier  │
│                                      │
│  To   :                              │
│        - Network verifier            │
└──────────────────────────────────────┘

```



3. **Verification:** Verifier(`v1`) communicates with the participating nodes and generates a challenge for the node which hosts the data(`node_2`). The challenge consists of the following steps:
* `node_2` should create a Merkle tree that matches the original Merkle root of `data_x` uploaded in the first place.
* `v1` decides the **order** and the **number of blocks/data** ranges to be sent to `node_1` by `node_2`. We don't want to reveal the order of blocks to `node_1` yet.
* `v1` asks `node_2` for a fixed range of data, which will be encrypted using a random key `k1` as `data_enc` by `v1` and sent to `node_1`.

At this stage, `node_1` has some `data_z`, plus some `data_enc` but has no knowledge on how to reassemble them in order to get the original file. Now, `v1` can validate the integrity of the data sent to `node_1` and if they match the original Merkle tree's identity, then the decryption key `k1` is sent to `node_1`. The order of the blocks will also be sent, so `node_1` can put all the parts together to reassemble the data. The final step is to release the fees to `node_2` by `v1`. 

With this algorithm, we simultaneously achieve Proof of Transfer and Proof of Data Posession.
```
            ┌───┬───┬───┬───┬───┬───┬───┬───┐
Data Blocks:│ a │ b │ c │ d │ e │ f │ g │ h │
            └───┴───┴───┴───┴───┴───┴───┴───┘
              0   1   2   3   4   5   6   7
              │   │   │   │   │   │   │   │
              └───┘   └───┘   └───┘   └───┘
               h01     h23     h45     h67
                │       │       │       │
                └───────┘       └───────┘
                h(h01+h23)     h(h45+h67)
                    │               │
                    │               │
                    └───────────────┘
         Merkle root:  h(h(h01+h23)+h(h45+h67))
```



# Installation

### Linux, macOS, and FreeBSD based systems

#### Installation requirements

1. Download and install golang

```
https://golang.org/doc/install
follow the instructions to install golang on your system
```

#### Compile FileFileGo for Linux, macOS, and FreeBSD

1. Download and Compile:

```
git clone https://github.com/filefilego/filefilego.git
cd filefilego/cli
go build -o filefilego .
```

2. Create Node Identity Key (Used for encryption and network identification)
   Replace **thisismynodespassword** with your own password

```
./filefilego account create_node_key thisismynodespassword
```

3. Create an account to send/receive coins.
   Replace **thisismypassword** with your own password

```
./filefilego account create thisismypassword
```

4. List the created accounts:

```
./filefilego account list

You will get json filenames that contain the address of your created account in step 3.
0x--------------------------------.json
```

5. Run the full node:

```
./filefilego --rpc --http --httpport=8090 --httpaddr=0.0.0.0 --bootstrapnodes="/ip4/77.247.178.110/tcp/10209/p2p/16Uiu2HAm1WKH57E4vku2rhLT3qMtP6GX5t5CxxoSmQnJWMHc6Lot"
```

The above command runs a full node and starts the http rpc server. In this case, we listen on all interfaces `0.0.0.0` and port `8090` so we can build an application that can interact with this full node.

### Windows

#### Install requirements for Windows

1. Install Go for windows

```
https://golang.org/dl/

Download: go1.14.4.windows-amd64.msi
and install the package
```

2. Install TDM-GCC

In order to compile the code on windows we need gcc. Download the TDM-GCC installer by visiting this page:

```
https://jmeubank.github.io/tdm-gcc/

Download tdm64-gcc-x.x.x.exe if you are on a 64-bit machine
-- or ---
Download tdm-gcc-9.2.0.exe if you are on a 32-bit machine

Most of the modern CPUs are 64-bit based so go for the first binary
```

3. Install Git on Windows

```
https://git-scm.com/download/win

Download:

64-bit Git for Windows Setup
-- or --
32-bit Git for Windows Setup
```

#### Compile FileFileGo for Windows

1. Download and Compile:
   Open a windows cmd/terminal and follow the instructions(use `dir` to navigate to your desired folder e.g. `C:/FileFileGo`):

```
git clone https://github.com/filefilego/filefilego.git
cd filefilego/cli
go build -o filefilego.exe .
```

2. Create Node Identity Key (Used for encryption and network identification)
   Replace **thisismynodespassword** with your own password

```
filefilego.exe account create_node_key thisismynodespassword
```

3. Create an account to send/receive coins.
   Replace **thisismypassword** with your own password

```
filefilego.exe account create thisismypassword
```

4. List the created accounts:

```
filefilego.exe account list

You will get json filenames that contain the address of your created account in step 3.
0x--------------------------------.json
```

5. Run the full node:

```
filefilego.exe --rpc --http --httpport=8090 --httpaddr=0.0.0.0 --bootstrapnodes="/ip4/77.247.178.110/tcp/10209/p2p/16Uiu2HAm1WKH57E4vku2rhLT3qMtP6GX5t5CxxoSmQnJWMHc6Lot"
```


# Architecture

In this section, we cover the disadvantages of different protocols and platforms to get clear picture and examine the weaknesses.

### XDCC

XDCC is a file-sharing method that is based on IRC to serve files.

| **XDCC Disadvantages**                                                                                   |
| -------------------------------------------------------------------------------------------------------- |
| Requires a centralized indexer/tracker/lister which is subject to censorship and single point of failure |
| Transfer protocol rather than a complete file sharing solution                                           |
| No built-in search functionality                                                                         |
| No incentive to retain data                                                                              |

### Usenet

Usenet is a distributed discussion system since 1980.

| **Usenet Disadvantages**                                                                                               |
| ---------------------------------------------------------------------------------------------------------------------- |
| Requires a centralized indexer/tracker/lister which is subject to censorship and single point of failure               |
| Requires subscription and forces user to pay - ( what if only one single file is needed?!)                             |
| Although Usenet providers retain data, it still lacks the incentive mechanism which motivates them to retain even more |

### BitTorrent

BitTorrent is a peer-to-peer file-sharing protocol that requires a client and trackers/DHT.

| **BitTorrent Disadvantages**                                                                              |
| --------------------------------------------------------------------------------------------------------- |
| Requires a centralized indexer/tracker/lister which is subject to censorship and single point of failure  |
| Inactive Torrents without seeders/Lack of incentive mechanism to reward peers for seeding                 |
| IP addresses are completely exposed. Anyone can see what user is downloading and uploading                |
| (Optional) Requires additional VPN and proxy services which are paid services, to solve the above problem |
| Penalty by ISPs for downloading files, usually require users to pay up to USD 200 - USD 5000              |
| Unstable download/upload speed                                                                            |

### Cyberlocker / Filehoster

A cyberlocker is a third-party online service that provides file-storing and file-sharing services.

| **Cyberlocker / Filehoster Disadvantages**                                                               |
| -------------------------------------------------------------------------------------------------------- |
| Requires a centralized indexer/tracker/lister which is subject to censorship and single point of failure |
| The Filehoster on its own is subject to censorship. (e.g megaupload was shut down by DOJ)                |
| Requires subscription and premium upgrades - ( what if only one single file is needed?!)                 |
| Extremely slow speeds which force users to pay for premium account                                       |
| Inactive files are deleted after a few months / Lack of incentive mechanism                              |

## FileFileGo Components

![](docs/images/ffg_design.png "Design")

### Features

FileFileGo combines the strength of Usenet, Blockchain/Cryptocurrency, DHT, and innovations behind BitTorrent to form a decentralized network that can't be censored and taken down by ISPs.

- Blockchain-based for indexing, tracking, and other network metadata and logic.
- Encrypted traffic to prevent ISPs and other third parties from traffic inspection.
- Privacy-first design, to relay traffic through a set of intermediate peers.
- The peer-to-Peer design replicates the state of the network on each full-node.
- Native cryptocurrency to work as the "fuel" of the network.
- Extremely low and conditional transaction fees compared to Ethereum/Bitcoin.
- Dynamic block size.
- Block-time of 10 seconds.
- RPC interface to build DApps.

### Blockchain Consensus Algorithm

Block-time of 10 seconds requires an appropriate consensus algorithm that doesn't waste much processing power and is efficient enough to process a high volume of transactions. For the first phase of FileFileGo, we choose to use Proof of Authority to achieve consensus, and later on a PoS mechanism will replace the current algorithm. PoW based algorithms are risky (PoW is safe by design) for new blockchains since there are already huge pools of computing power out there and can be used to perform 51% attacks.

#### Proof of Authority / Validator+Verifier Algorithms

Validator's identities are hardcoded within the blockchain and can be verified by the Genesis block coinbase transaction. The verification by participating nodes is a simple process of checking the block's signatures.

#### Proof of Stake

In the future, proof-of-stake will eventually replace the current PoA mechanism so different parties can participate in the block mining process. In terms of blockchain governance, we want more parties and developers to get involved and increase the stakeholders, and one of the incentives is the Proof-of-Stake mechanism.

### Blockchain and Metadata/Accounting

When it comes to transaction and state mutation, we choose a different approach from UTXO-like structures to eliminate complexity. In FileFileGo accounting and metadata are stored like a normal database row while the raw blocks are stored in original format within the database.

# Technical Details

In this section, we will introduce technical terms and concepts used in FileFileGo.

### Channels

Channels allow users to organize and group data. It's similar to a bucket or a folder. For example, all the content on Wikileaks can be placed within a channel called "Wikileaks". The channel creator inherits all the permissions required for updates and other channel-related functionalities. Channels are represented in a node-chain format and are denoted as a node without `ParentHash`

### Sub Channel

The concept of a sub-channel is to be able to categorize data even further. For instance, documents, pictures, or music.

### Entry & File/Directory

In filefilego an `Entry` represents a post or a piece of data that contains more information about the entry itself rather than categorization/ordering. `File` and `Directory` can be placed into an `Entry`.

### Data Storage Layer ("BINLAYER")

`Binlayer` is the storage layer that tracks binary data, which are used by hash pointers within the blockchain to refer to a piece of data. The `ChanNode` structure has a field called `BinlayerHash` which refers to the binary hash and is in the form of `"{HASH_ALGORITHM}:>{DATA_HASH}"`. We would like to keep the metadata of the hashing algorithm used as it might be useful in the future.

### Full-text Index/Search

Search accuracy and flexibility are as important as the core blockchain. The aim is to be able to build complex queries including binary searches using a specific query language. For instance, we should allow queries of these types:
1. Required or inclusive ("filefilego coin"), which means both "filefilego" and "coin" is required.
2. Optional or exclusive ("filefilego currency"), which means one of those words can be excluded.

The development of a query language that allows complex queries is a powerful tool that can be used to increase the accuracy of the search engine.

There is the option to disable the full-text indexing functionality of a node by using the `--fulltex` cli flag.

### Binlayer Storage Engine

Binlayer is the storage layer that keeps track of binary files and uses hashes to represent a piece of information within the blockchain. This feature can be turned on by using the following flags:

```
... --binlayer --binlayerdir="/somewhere/to/store/data" --binlayer_token="somelongtokenhere" ...
```

`--binlayerdir` should be a directory that exists with appropriate read/write permissions. Please note that full nodes can work without this mechanism. `binlayer_token` is a token that grants admin rights to a token so it can create other tokens using the HTTP API. This is useful when access right is needed by web apps or distinct users.

# Coin Distribution

### The Coin

| Unit                     | Value                  |
| ------------------------ | --------------------------------- |
| **FFGOne**               | **1**                             |
| **KFFG**                 | **1.000**                         |
| **MFFG**                 | **1.000.000**                     |
| **GFFG**                 | **1.000.000.000**                 |
| **MicroFFG**             | **1.000.000.000.000**             |
| **MiliFFG**              | **1.000.000.000.000.000**         |
| **FFG** (Default unit)   | **1.000.000.000.000.000.000**     |
| **ZFFG**                 | **1.000.000.000.000.000.000.000** |

**Total Supply:** 500 Million FFG
**Validation/Stake Reward:** 15 FFG per Block
**Supply Decrease Rate:** Divide by 2 every 24 months