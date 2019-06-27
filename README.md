# The Algorithms That Keep Us Safe

By now, it's fairly common knowledge just how vital encryption is to the safety of our digital lives.
But what isn't well known is the genius algorithms that provide the foundation for today's encryption.
In order to get up to speed on the state of encryption, I decided to do my own implementation on a few of the most popular algorithms.

## Secure Hashes and Message Digests

While traditional encryption is typically a two way process, hashes and message digests are a one way method of scrambling data.
Hashes are useful when there's no reason to be able to get the original data back out. 
Databases use hashing to store passwords, and browsers can use hashing to verify the data sent by a website matches the data you were meant to download.


#### Implementing MD5

One of the most popular hashing algorithms is the MD5 hashing function. 
With [RFC 1321](https://tools.ietf.org/html/rfc1321) in hand, I was ready try my own implementation.
I found it easiest to follow the process step by step, as the algorithm is described with a wealth of detail.
In the end it took only 50 lines of useful code to achieve.

#### What I Learnt

Implementing the MD5 hashing function took me as far away from my regular Python web development as I could get.
It's not everyday you get to use byte arrays and bitwise operators, and it was eye opening to see a different side of programming.
While everything was a little slower than usual, finishing a complex algorithm start to scratch in sub 2 hours was a win in my books.

As most binary representations of data are well and truly abstracted in everyday business software, I was introduced to the new concepts of big- and little-endian.
Getting these right, and finding easy ways of transferring between them was one of the biggest sticking points of the challenge.
