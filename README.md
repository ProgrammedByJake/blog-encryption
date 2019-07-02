# The Algorithms That Keep Us Safe

By now, it's fairly common knowledge just how vital encryption is to the safety of our digital lives.
But what isn't well known is the genius algorithms that provide the foundation for today's encryption.
I wanted to know just how different kinds of encryption worked.
In order to get up to speed on the state of encryption, I decided to do my own implementation of a few of the most popular algorithms.

## Secure Hashes and Message Digests

While traditional encryption is typically a two way process, hashes and message digests are a one way method of scrambling data.
Hashes are useful when there's no reason to be able to get the original data back out. 
Databases use hashing to store passwords, and browsers can use hashing to verify the data sent by a website matches the data you were meant to download.
They simply compare the hash of the correct data with the data that you provide and if they don't match, you're incorrect.
As they are generally output a fixed length hash, there are many inputs that can create the same output.


#### Implementing MD5

One of the most popular hashing algorithms is the MD5 hashing function. 
With [RFC 1321](https://tools.ietf.org/html/rfc1321) in hand, I was ready try my own implementation.
I found it easiest to follow the process step by step, as the algorithm is described with a wealth of detail.
In the end it took only 2 hours and 50 lines of useful code to achieve.

#### What I Learnt

Implementing the MD5 hashing function took me as far away from my regular Python web development as I could get.
It's not everyday you get to use byte arrays and bitwise operators, and it was eye opening to see a different side of programming.
While everything was a little slower than usual, finishing a somewhat complex algorithm start to finish in sub 2 hours was a win in my books.

As most binary representations of data are well and truly abstracted in everyday business software, I was introduced to the new concepts of big- and little-endian.
Getting these right, and finding easy ways of transferring between them was one of the biggest sticking points of the challenge.

## Symmetric Encryption

Moving on up in terms of complexity, symmetric encryption is any kind of encryption algorithm in which the encryption and decryption processes are done using the same key.
Unlike hashing which generally produces a fixed length hash, symmetric encryption produces ciphertext proportional to the size of the input plaintext.

#### Implementing AES

Again, going with one of the most popular in the category, I decided to implement the AES algorithm.
With [NIST FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) in hand this time, I was back at it again. 
Again, much of the implementation can be done step by step, as each section defines a single function.
What was most helpful in this document was the in-depth appendices, that ran through an example encryption process step by step.
This gave me a variety of test cases for each individual function, allowing me to debug and test piece by piece rather then as a whole. 

#### What I Learnt

While programmatically it wasn't too different from MD5, the additional complexities meant that I ended up doing a refactor partway through to make it more class-based.
Where this algorithm really challenged me was introducing new forms of mathematics. 
Galois fields (also known as finite fields) introduce a new set of basic operations that I implemented myself.
While libraries such as pyfinite are available to handle finite fields, if I was using libraries this whole challenge is useless.

## Roadmap

- Asymmetric Encryption - RSA
- Message Authentication Codes - HMAC
- Block Cipher Modes - ECB & CBC