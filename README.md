# akcencrypt
端到端加密实现 SM2+SM3+SM4

#sm2
SM2使用了https://github.com/Aries-orz/nano-sm2
实现了SM2推荐曲线公私钥生成，ECDH，ECDSA

#sm3
使用了goldboar(goldboar@163.com)实现的代码，修复不同平台上的兼容问题

#sm4
使用了goldboar (goldboar@163.com)实现的代码

#JNI
java调用接口 AKCEncryptWrapper
使用JNI NDK编译
