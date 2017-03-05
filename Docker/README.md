<img src="https://github.com/rawrtc/rawrtc/blob/master/media/rawrtc-icon-256.png" width="48"> + <img src="https://github.com/docker/docker/blob/master/docs/static_files/docker-logo-compressed.png" width="96"> 
# RAWRTC Build Environment for Docker 

This folder contains a functioning environment to run the RAWRTC build process inside a new Linux based docker instance.
One of the major advantages of RAWRTC is the removal of non DataChannel functions from the native WebRTC stack, dramatically simplifying the deployment on server based systems. Unlike WebRTC native, RAWRTC does not require media drivers (e.g. Pulse Audio of Fake* Video/Audio drivers) to function. This makes RAWRTC ideal so server side applications which focus on the DataChannel implementation of WebRTC.

## Notes
Currently the base `Dockerfile` has a functional RAWRTC build process on the latest Ubuntu release.
Additional Dockerfiles (e.g. Ubuntu 14.04 and earlier) can be used by simply changing the base image in Line 1 of the file 
```
FROM ubuntu;latest
```

To something like
```
FROM ubuntu:14.04
```
This is especially useful for generating static binaries where you need to ensure compatibility with older Glibc installations.
***

## Docker Example

The first step is to [install docker link] https://docs.docker.com/engine/installation/linux/ubuntu/

Once Docker is installed and available, running the base is simple:

``` bash
git clone -b dev_docker https://github.com/jacobloveless/rawrtc
cd rawrtc/docker

# build the docker image, and tag (t) it with a name
# docker build <imagefile> -t <tag name>
docker build Dockerfile -t rawrtc

# run a version of the newly build image and get a shell
# we are going to run docker interactively (i) with pseudo tty (t) (for terminal access)
docker run -it rawrtc bash
``` 

You should now be in a shell of the build environment
```
docker run -it rawrtc bash
root@9bf90c7aba3e:/rawrtc# data-channel-sctp 1 9999
[000000000] data-channel-sctp-app: Init
[000000029] helper-handler: (A) ICE gatherer state: gathering
[000000030] (A) ICE gatherer local candidate: foundation=ac110006, protocol=udp, priority=1, ip=172.17.0.6, port=38503, type=host, tcp-type=N/A, related-address=N/A, related-port=0; URL: N/A; enabled
[000000216] (A) ICE gatherer local candidate: foundation=45a21011, protocol=udp, priority=1, ip=69.162.16.16, port=54571, type=srflx, tcp-type=N/A, related-address=172.17.0.6, related-port=38503; URL: N/A; enabled
[000000216] helper-common: (A) ICE gatherer last local candidate
[000000217] data-channel-sctp-app: Local Parameters:
{"iceParameters":{"usernameFragment":"PWTL1Mx4","password":"FPLAZsFjbVBmJgYWnZxdNVDpiAeL3FlZ","iceLite":false},"iceCandidates":[{"foundation":"ac110006","priority":1,"ip":"172.17.0.6","protocol":"udp","port":38503,"type":"host"},{"foundation":"45a21011","priority":1,"ip":"69.162.16.16","protocol":"udp","port":54571,"type":"srflx","relatedAddress":"172.17.0.6","relatedPort":38503}],"dtlsParameters":{"role":"auto","fingerprints":[{"algorithm":"sha-256","value":"DE:D1:98:DE:6C:E8:F6:97:84:E0:8D:14:77:8A:BA:93:73:24:EF:14:38:8C:B8:F5:17:71:A3:C6:D7:AF:00:E4"}]},"sctpParameters":{"maxMessageSize":0,"port":9999}}
[000000217] helper-handler: (A) ICE gatherer state: complete
^C[000001871] helper-handler: Got signal: 2, terminating...
[000001871] helper-handler: (A) Data channel closed: cat-noises
[000001872] helper-handler: (A) SCTP transport state change: closed
[000001872] helper-handler: (A) DTLS transport state change: closed
[000001872] helper-handler: (A) ICE gatherer state: closed
root@9bf90c7aba3e:/rawrtc# ls -l
total 40
-rw-r--r-- 1 root root 1760 Mar  3 15:41 CMakeLists.txt
-rw-r--r-- 1 root root 1318 Mar  3 15:41 LICENSE
-rw-r--r-- 1 root root 1849 Mar  3 15:41 Readme.md
drwxr-xr-x 6 root root 4096 Mar  3 15:41 build
drwxr-xr-x 2 root root 4096 Mar  3 15:41 htdocs
-rwxr-xr-x 1 root root 7644 Mar  3 15:41 make-dependencies.sh
drwxr-xr-x 2 root root 4096 Mar  3 15:41 media
-rw-r--r-- 1 root root 1041 Mar  3 15:41 meson.build
drwxr-xr-x 5 root root 4096 Mar  3 15:41 src
root@9bf90c7aba3e:/rawrtc#
```
