NCrypt
======
NCrypt is a .Net Standard C# library to sign string and byte-array messages, and to verify their signatures. It makes use of the RSA asymmetric, public-key cryptosystem.

This is an educational library aimed to ease workshops on BlockChain and cryptocurrencies (see [neat-coin](http://github.com/arialdomartini/neat-coin/)). It is not intented to be used in mission-critical, production systems.

## Install
NCrypt is available as a NuGet Package. Install it with:

```bash
dotnet add package Pie.NCrypt
```
 
or
 
```bash
PM> Install-Package Pie.NCrypt
```

## Build from source
If you prefer to compile the library from the source code, follow the instructions in the page [Building from source code](docs/building.md).

## Usage
### RSA Signature
Create an instance of `RSA`:

```csharp
var rsa = new Pie.NCrypt.RSA();
```

In order to sign messages and verify signatures you need a RSA Private Key and its corresponding Public Key.

You can create one public/private key pair with:

```csharp
var pair = rsa.GenerateKeyPair();
```

which returns a structure with 2 random RSA keys:

```csharp
Console.WriteLine(pair.PrivateKey);

/* MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIYjrEkSdzWUOs/+7vUCtQCeCLjceCsNOoESEHOWQcq7fYtBJ
myNXESRfLlmpW4RgKNBIa7oT+PqQ+jLnqnUHz8WcdE2IUidXqj6YIEJlwa18+R0lJ/eRYIunBA9nFX1rZT2S3ia70XQ+nAdgIwI
Zpl7LYfyUFcafPsMIz91gZAgMBAAECgYACzRgKu/aNAgpDu7hiDh4qpuIxhG695FH8jhDyp+KuhJjBK880S2m9SlLjELVI7j9jD
VV+t2LCgUNQ2CN0Ilvyh/GYDpJrRSQbLdArzU/KZDyUR8TNlD4kyilsvQL5ey7ox1do2LGZdCk7W+DU1UOEIo3Zp84rzrY2gHnL
Dpv6LQJBAPjBU3Nt9rX/rhtnHf5J8tAfdzFhUR7KyXh+7hWVA54lcP24SAH0KbFLHpNqbkVEYGkEX0cLECjWTw8Knr8RJiUCQQC
KC8q7AjmSOXlipHTM0P+vhHDx5CpiizT4a2MnW0YALWaMSizmcQeWbb6eXWG6VsB0nO3dfY7KF8fAoc3244XlAkADMyFqq7BvuO
E5cwMcwUDBUpZK6VCMz9j1ltRjLK6GOz8P1G4AsG5U3H2BMe5HL9D5qNe85zSHAfK0Y9OU65iNAkAt1kaFm/KD1COzFkpWK9uKa
x6ZoxpTyEdZaUbuLYdrzadsU8De748GawBNU1J87gtPbUAqOGOuRQElvFRIcznlAkAa5/BgIohCskelV3S70jLo2p/SNKi9A5lC
jglAiQ9YukPEx4PQQQqz2P5qH3zjNHwPiTs4jStT1q9ogARlHGMwqo */


Console.WriteLine(pair.PublicKey);

/* MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCGI6xJEnc1lDrP/u71ArUAngi43HgrDTqBEhBzlkHKu32LQSc6psjVxEkX
ZqVuEYCjQSGu6E/j6kPoy56p1B8/FnHRNiFInV6o+mCBCZcGtfPkdJSf3kWCLpwQPZxV9a2U9kt4mu9F0PpwHYCMCGaZey2H8lB
XGnz7DCM/dYGQIDAQABy5 */
```


Signing a string message with the Private key creates a Signature:

```csharp
var signature = rsa.Sign("some message", pair.PrivateKey);
Console.WriteLine(signature);

/* FCBt0OjEgrgEZuhfUjpgPvCbCrc1gXZEFi05iKIopi8OJrZcdIaVgWREy7kZHSGGMsecmOOugNtJXCY+fHnPyDp4eK73S9cWJ
NfUnB+pEm5XlxI82cKMn4Bvxr1CXrLv6PwFyGCUykv4CWP5SEHhkMuLEFTZRQ/3XcrgzkgerAE= */
```

The authenticity of the message signature can be verified by using the message itself, the provided Signature value and the Public Key corresponding to the Private Key used to sign the message:

```csharp
var isValid = rsa.Verify("some message", signature, pair.PublicKey);  // true
```

If either:

* the signature has been faked
* the Private Key that signed the message is not corresponding to the Public Key used during the verification;
* the Message has been modified;

the verification fails and returns `false`.


### Calculating SHA1 hashes
Use:
```csharp
var someObject = new SomeObject{ Field1 = "some value", Field2 = "second value"};

var hash = new SHA1().HashOf(someObject);
```

Classes can be private or anonymous.

```csharp
var someObject = 
    new {
        Field1 = "some value 1",
        Field2 = "some value 2",
        Field3 = 100
    };

var hash = new SHA1().HashOf(someObject);

// HYXB+T6Eq5vxKBa6elmT4Av/a4A=
```

Hash is calculated against public fields and properties. Private elements are ignored.
