# scan-o-mat
simple ping sweep script that uses async sockets to scan 512 IPs almost parallel

Example
```
sudo python3 scan-o-mat.py 192.168.178.0/24
192.168.178.1 -> response: 0.05749177932739258
192.168.178.21 -> response: 0.004856109619140625
192.168.178.29 -> response: 0.018185853958129883
192.168.178.36 -> response: 0.0241701602935791
192.168.178.46 -> response: 0.021260976791381836
192.168.178.63 -> response: 0.07855582237243652
192.168.178.72 -> response: 0.16544485092163086
192.168.178.73 -> response: 0.16835379600524902
192.168.178.21 -> response: 0.0053920745849609375
1.85933518409729
```
