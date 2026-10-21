# Ten-minute Mini-UPI demo

1. **(0:00)** Show the simulation ribbon and explain that balances are virtual.
2. **(1:00)** Log in, bind the browser device, and show the non-extractable key.
3. **(2:30)** Pay a VPA with the amount pad and MPIN.
4. **(4:00)** Open Security Lens: device signature, AES-GCM envelope, PSP
   certificate, HMAC, bank receipt, and audit hash chain.
5. **(5:30)** Enable Demo tamper test. The modified ciphertext is rejected.
6. **(6:30)** Replay the captured request. The nonce is rejected.
7. **(7:30)** Try a valid token with another device key. Device binding rejects it.
8. **(8:30)** Run `make attacks`; point out `PASS = attack blocked`.
9. **(9:15)** Run audit verification and show the chain status.
10. **(9:45)** Close with the simulation limitations and future HSM work.
