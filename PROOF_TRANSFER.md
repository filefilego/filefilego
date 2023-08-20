# Proof of Transfer

PoX and PoDP are both part of the Data Verification Consensus category, which are utilized to verify and challenge data transfer contracts. These mechanisms are essential for enabling us to determine, in a deterministic and mathematically sound manner, whether a node has effectively transferred data within the network. Without these mechanisms, this process would be unfeasible.

For more information please check: https://filefilego.com/documentation/docs/consensus.html#proof-of-transfer-pox-proof-of-data-possession-podp

## Algorithm

Let $x$ be the input file containing content divided into $N = 1024$ segments.

1. Divide the content of file $x$ into $N$ segments: 
   $x = (x_1, x_2, \ldots, x_N)$

2. Calculate the Merkle Tree hash of the segments:
   Let $h(x_i)$ represent the hash of segment $x_i$.
   Construct the Merkle Tree by hashing adjacent segments in a binary tree structure:
   
   $h(x_i) = \text{HashFunction}(x_i)$
   $h(x_{i,j}) = \text{HashFunction}(h(x_i) \| h(x_j))$
   where $\|$ denotes concatenation.
   The root hash of the Merkle Tree is $h_{\text{root}} = h(x_{1,2})$, representing the overall content.

3. Shuffle the segments:
   Let $\pi$ be a permutation representing the shuffling of segments.
   $\pi : \{1, 2, \ldots, N\} \rightarrow \{1, 2, \ldots, N\}$
   The shuffled segments are:
   $x_{\pi(1)}, x_{\pi(2)}, \ldots, x_{\pi(N)}$

4. Encrypt 1 percent of the shuffled segments:
   Let $M = \lfloor 0.01 \times N \rfloor$ be the number of segments to be encrypted.
   Let $E(x_i)$ represent the encryption of segment $x_i$.
   The encrypted segments are:
   $E(x_{\pi(1)}), E(x_{\pi(2)}), \ldots, E(x_{\pi(M)})$


#### The verification process


1. Decryption of Encrypted Segments:
   For each of the $M$ encrypted segments, apply the decryption function $D(E(x_{\pi(i)}))$ to obtain the decrypted version of the segment $x_{\pi(i)}$:
   
   $x_{\pi(i)}' = D(E(x_{\pi(i)}))$

2. Restoring the Shuffled Order:
   Since the segments were shuffled during the encryption process, they need to be restored to their original order using the inverse permutation $\pi^{-1}$:
   
   $x' = (x_{\pi^{-1}(1)}', x_{\pi^{-1}(2)}', \ldots, x_{\pi^{-1}(M)}')$

3. Merkle Tree Hash Calculation:
   Recalculate the Merkle Tree hash of the decrypted segments in the restored order. Construct the hash tree similarly to the original construction, but use the decrypted segments $x'$:
   
   $h'(x_i') = \text{HashFunction}(x_i')$
   $h'(x_{i,j}') = \text{HashFunction}(h'(x_i') \| h'(x_j'))$
   
4. Finally, the derived original Merkle root hash $h'_ \text{root}$ is obtained by hashing the two children of the root hash $h'_ \text{root} = \text{HashFunction}(h'(x_{1,2}') \| h'(x_{3,4}'))$.
5. Consensus is achieved if the derived merkle root hash matches the original merkle root hash.

## Calculating Merkle Root Hash

Consider a scenario involving a file containing the subsequent content:

```
FileFileGo_Network
```

Upon uploading a file to a storage provider, the merkle root hash of the file is computed through the segmentation of its content into distinct data segments.

The ensuing illustration depicts a simplified manifestation of the file's arrangement on the storage medium. Each individual box within the illustration symbolizes 1 byte of data.
```
┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
│ F │ i │ l │ e │ F │ i │ l │ e │ G │ o │ _ │ N │ e │ t │ w │ o │ r │ k │
└───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
```

To find the merkle root hash of this file, we break the file into smaller parts. For example, let's split the file into nine sections, and each part will have only two bytes.
```

    0       1       2       3       4       5      6       7        8
┌───────┬───────┬───────┬───────┬───────┬───────┬───────┬───────┬───────┐
│ F   i │ l   e │ F   i │ l   e │ G   o │ _   N │ e   t │ w   o │ r   k │
└───────┴───────┴───────┴───────┴───────┴───────┴───────┴───────┴───────┘
```

Now we take the hash of each segment:
```
segment 0: hash("Fi"), denoted by h0
segment 1: hash("le"), denoted by h1
segment 2: hash("Fi"), denoted by h2
segment 3: hash("le"), denoted by h3
segment 4: hash("Go"), denoted by h4
segment 5: hash("_N"), denoted by h5
segment 6: hash("et"), denoted by h6
segment 7: hash("wo"), denoted by h7
segment 8: hash("rk"), denoted by h8
```


and then we calculate the merkle root hash of the file by applying the algorithm.


Here's an example of how this algorithm operates:

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

Now, we possess a merkle root hash for the file, represented as mt(f), which is essentially another hash value.


## Data Request

When a request to retrieve data reaches a storage provider, the provider rearranges the data segments in a random order. For instance, consider the sequence of data segments:

`random segments [ 1, 5, 2, 4, 7, 6, 3, 0, 8 ]`, which translates to the following arrangement:

```

   1       5        2       4      7        6       3       0       8

┌───────┬───────┬───────┬───────┬───────┬───────┬───────┬───────┬───────┐
│ l   e │ _   N │ F   i │ G   o │ w   o │ e   t │ l   e │ F   i │ r   k │
└───────┴───────┴───────┴───────┴───────┴───────┴───────┴───────┴───────┘
```

Subsequently, the provider generates a symmetric key and initialization vector (IV) to encrypt a portion of these segments. In this illustration, we'll opt for encrypting 25% of the segments, which equates to 2 segments. Furthermore, we'll encrypt every 4 segments, implying that we will encrypt the 0th and 4th segments:

```
                       25% Segment Encryption = 2 segments

┌───────┬───────┬───────┬───────┬───────┬───────┬───────┬───────┬───────┐
│ l   e │ _   N │ F   i │ *   * │ w   o │ e   t │ l   e │ *   * │ r   k │
└───────┴───────┴───────┴───────┴───────┴───────┴───────┴───────┴───────┘
```

Now, the aforementioned data will be provided to the data requester. Simultaneously, the key/IV, the randomized order of segments, and the contents of segments 0 and 4 are transmitted to the `data verifier`. It's important to highlight that the downloader possesses `Zero-Knowledge` regarding both the order of segments within the file and the encryption key/IV.

You might be concerned about the possibility of someone creating a script to attempt various combinations of segments to determine the original order, potentially leading to a security vulnerability and a potential attack.

To provide further insight, consider that a file is divided into approximately 1024 segments (or slightly fewer) in a real-world scenario, and these segments are then randomized. For an attacker to reconstruct the original segment order, they would need to carry out a "permutation without repetition." The total count of ways to arrange these file segments is given by n! (factorial), which amounts to 1024! in this instance. (https://coolconversion.com/math/factorial/What-is-the-factorial-of_1024_%3F)


The attacker's subsequent step involves attempting to acquire the key and IV used for encrypting the two segments. However, it's worth noting that this task is currently considered impossible based on existing vulnerabilities in the field.


Following this, the file downloader must request the encryption key/IV and the randomized order of file segments from a designated `data verifier` within the network.

## Verification

The data downloader sends a request to the data verifier, seeking the encryption key/IV and the randomized segments. This request is accompanied by the segment hashes of the downloaded file, which are presented as follows:

```
h1
h5
h2
h(enc(4))
h7
h6
h3
h(enc(0))
h8
```

The `data verifier` undertakes encryption and hashing for segments 0 and 4, resulting in the following hash values:

```
h1
h5
h2
h4
h7
h6
h3
h0
h8
```

Lastly, the `data verifier` reorganizes the segments according to the randomized order generated by the file hoster during the data transfer to the requester. This process yields the original sequence of segment hashes:
```
h0
h1
h2
h3
h4
h5
h6
h7
h8
```

Ultimately, through the execution of the merkle root hash computation, the data verifier deduces the original merkle root hash without necessitating complete local access to the entire file content.

Upon confirming that the derived merkle root hash matches the original one, we have effectively established a mathematical proof that the data downloader possesses all the requested data. Subsequently, the data verifier transmits the encryption key/IV and the randomized segments order to the data downloader, leading to the automatic release of fees to the file hoster.