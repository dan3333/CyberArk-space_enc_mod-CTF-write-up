from fcntl import ioctl
import subprocess
#import ipdb; ipdb.set_trace()
for i in range(256):
    f= open ('/dev/sem','wb')
    ioctl(f,0,bytes([i]))
    f.close()

    p = subprocess.run(["cat", "/dev/sem"], capture_output=True)
    print(f"Input byte: {i}")
    print(p.stdout.decode('utf-8',errors='ignore'))
    
