# Creating a new Hyper-V image

1. Create an old generation VM:
```
New-VM -Name "OpenCanary" -MemoryStartupBytes 2GB -Version 11.0
```
1. Create a new Gen 1 virtual HD, 6GB in size
1. Boot Debian 12 amd64 netist ISO, install debian on /dev/sda (whole disk), hostname opencanary, no GUI, no SSH, no HTTP, user root/root and opencanary/opencanary
1. Inside this repo, run `$ python -mhttp.server`, and login to the Debian VM as root, then run:
```
$ wget http://x.x.x.x:8000/install.sh
$ ./install.sh
```

# VM storage

It resides in opencanary-hyperv-image in eu-west-1 in the 8965... account