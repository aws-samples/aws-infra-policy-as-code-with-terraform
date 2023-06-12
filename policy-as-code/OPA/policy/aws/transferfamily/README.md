Following TRANSFER-FAMILY Controls are implemented:

1. aws-transferfamily-m-1: Ensure neither FTP nor any plain-text protocol should be used for data transfer
2. aws-transferfamily-m-2: SSH keys should not be used for authentication
3. aws-transferfamily-m-3: Data gathered and accessed by the service is over TLS protected channel. All communication inside the cluster must be encrypted
4. aws-transferfamily-m-4: AWS Transfer family server should NOT be publicly accessible over the internet