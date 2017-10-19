# iOS加密：AES+Base64
本篇文章记录了iOS中对字符串进行AES加密+Base64编码的过程，考虑到加密对象和使用场景，理所当然的将加密过程丢到了NSString的类别中，即下面说到的`NSString+AES`。

#### 一、对AES认识有以下几点（针对开发中涉及到的，其他的也没有深入研究了）：使用上总结起来就是——“保持一致”

#### 特别要注意的：如果你想使用密钥偏移量IV 那你的加密模式必须为CBC，不能使用别的模式了，具体关于加密参数，文章最后附上构造方法的参数文档。
*  AES有多种加密模式：`ECB``CBC``CFB``OFB`至于用哪个看你心情了，但是要同WebService同学保持一致；
*  加密解密过程需要你提供一个Key，一定是和WebService同学约定好的，不然是解密不了的；
*  密钥偏移量（IV）：非必须的，不过如果想加的话规则同上：“保持一致”；
*  补码方式：`PKCS7Padding` `PKCS5Padding`

对AES的认识可以通过类似 `http://www.seacha.com/tools/aes.html` 的在线加密网站，从UI上简单看看构成。


另外，在学习使用的时候看到网上一般有两种Base64编码方式：

*  `NSData_Base-64 Encoding`：NSData类中自带的编码方法；
*  `GTMBase64`：我记得是Google的，具体的我也记不住了【这里吐下槽：搜了一下GTMBase64这个关键词，所有人都说“这个是啥就不说了，大家都说烂了!@#$%^&*诸如此类的话”，到头来也没找到一个正经的 666】

Demo中两种编码方式都给大家写了，根据个人喜好选择。GTMBase64库可以用CocoaPods导入。

#### 下面是代码：

创建NSString的AES类别

```
#import <Foundation/Foundation.h>

@interface NSString (AES)

/**< 加密方法 */
- (NSString*)aci_encryptWithAES;

/**< 解密方法 */
- (NSString*)aci_decryptWithAES;

@end

```
.m文件 加密解密需要导入这两个头文件（其实只导入第二个就够了）

```
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
```
使用GTMBase64的话需要导入#import "GTMBase64.h"

定义加密的Key和向量IV

```
static NSString *const PSW_AES_KEY = @"TESTPASSWORD";
static NSString *const AES_IV_PARAMETER = @"AES00IVPARAMETER";

@implementation NSString (AES)

- (NSString*)aci_encryptWithAES {

    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding];
    NSData *AESData = [self AES128operation:kCCEncrypt
                                       data:data
                                        key:PSW_AES_KEY
                                         iv:AES_IV_PARAMETER];
    NSString *baseStr_GTM = [self encodeBase64Data:AESData];
    NSString *baseStr = [AESData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    
    NSLog(@"*****************\nGTMBase:%@\n*****************", baseStr_GTM);
    NSLog(@"*****************\niOSCode:%@\n*****************", baseStr);
    return baseStr_GTM;
}

- (NSString*)aci_decryptWithAES {

    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding];
    NSData *baseData_GTM = [self decodeBase64Data:data];
    NSData *baseData = [[NSData alloc]initWithBase64EncodedString:self options:0];
    
    NSData *AESData_GTM = [self AES128operation:kCCDecrypt
                                         data:baseData_GTM
                                          key:PSW_AES_KEY
                                           iv:AES_IV_PARAMETER];
    NSData *AESData = [self AES128operation:kCCDecrypt
                                         data:baseData
                                          key:PSW_AES_KEY
                                           iv:AES_IV_PARAMETER];
    
    NSString *decStr_GTM = [[NSString alloc] initWithData:AESData_GTM encoding:NSUTF8StringEncoding];
    NSString *decStr = [[NSString alloc] initWithData:AESData encoding:NSUTF8StringEncoding];
    
    NSLog(@"*****************\nGTMBase:%@\n*****************", decStr_GTM);
    NSLog(@"*****************\niOSCode:%@\n*****************", decStr);
    
    return decStr;
}
```
AES加解密算法

```
/**
 *  AES加解密算法
 *
 *  @param operation kCCEncrypt（加密）kCCDecrypt（解密）
 *  @param data      待操作Data数据
 *  @param key       key
 *  @param iv        向量
 *
 *  @return
 */
- (NSData *)AES128operation:(CCOperation)operation data:(NSData *)data key:(NSString *)key iv:(NSString *)iv {

    char keyPtr[kCCKeySizeAES128 + 1];	//kCCKeySizeAES128是加密位数 可以替换成256位的
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    // IV
    char ivPtr[kCCBlockSizeAES128 + 1];
    bzero(ivPtr, sizeof(ivPtr));
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    size_t bufferSize = [data length] + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    
    // 设置加密参数
    //（根据需求选择什么加密位数128or256，PKCS7Padding补码方式之类的_(:з」∠)_，详细的看下面吧）
    CCCryptorStatus cryptorStatus = CCCrypt(operation, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                            keyPtr, kCCKeySizeAES128,
                                            ivPtr,
                                            [data bytes], [data length],
                                            buffer, bufferSize,
                                            &numBytesEncrypted);
    
    if(cryptorStatus == kCCSuccess) {
        NSLog(@"Success");
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
        
    } else {
        NSLog(@"Error");
    }
    
    free(buffer);
    return nil;
}
```
GTMBase64编码

```
/**< GTMBase64编码 */
- (NSString*)encodeBase64Data:(NSData *)data {
    data = [GTMBase64 encodeData:data];
    NSString *base64String = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return base64String;
}

/**< GTMBase64解码 */
- (NSData*)decodeBase64Data:(NSData *)data {
    data = [GTMBase64 decodeData:data];
    return data;
}
```
完成！你就可以去跑,去跳,去做一个漂亮的倒挂金钩了~

Demo下载地址：https://github.com/iOSAppleBea/AES

##附：CCCryptorStatus构造
关于加密参数CCCryptorStatus，构造他可以使用`CCCrypt` `CCCryptorCreateWithMode` `CCCryptorCreate`等好多种方法，构造时对参数的使用还是比较麻烦的，看文档对英语渣来说很辛苦，大概说一下看过`CCCrypt`后了解的几点

```
苹果文档
/*!
    @function   CCCrypt
    @abstract   Stateless, one-shot encrypt or decrypt operation.
                This basically performs a sequence of CCCrytorCreate(),
                CCCryptorUpdate(), CCCryptorFinal(), and CCCryptorRelease().
    
    @param      alg             Defines the encryption algorithm.
    
    
    @param      op              Defines the basic operation: kCCEncrypt or kCCDecrypt.
    
    @param      options         A word of flags defining options. See discussion
                                for the CCOptions type.
    
    @param      key             Raw key material, length keyLength bytes. 
                                加解密的密钥
    
    @param      keyLength       Length of key material. Must be appropriate 
                                for the select algorithm. Some algorithms may 
                                provide for varying key lengths.
                                参数解释详见苹果文档中的一个Key Size的枚举
                                enum {
    											kCCKeySizeAES128          = 16,
    											kCCKeySizeAES192          = 24,
    											kCCKeySizeAES256          = 32,
    											kCCKeySizeDES             = 8,
    											kCCKeySize3DES            = 24,
    											kCCKeySizeMinCAST         = 5,
    											kCCKeySizeMaxCAST         = 16,
    											kCCKeySizeMinRC4          = 1,
    											kCCKeySizeMaxRC4          = 512,
    											kCCKeySizeMinRC2          = 1,
    											kCCKeySizeMaxRC2          = 128,
    											kCCKeySizeMinBlowfish     = 8,
    											kCCKeySizeMaxBlowfish     = 56,
											};
    
    @param      iv              Initialization vector, optional. Used for 
                                Cipher Block Chaining (CBC) mode. If present, 
                                must be the same length as the selected 
                                algorithm's block size. If CBC mode is
                                selected (by the absence of any mode bits in 
                                the options flags) and no IV is present, a 
                                NULL (all zeroes) IV will be used. This is 
                                ignored if ECB mode is used or if a stream 
                                cipher algorithm is selected. 
                                向量：大概意思说，此属性可选，但只能用于CBC模式。
                                如果出现那么他的长度必须和算法的block size保持一致。
                                如果是因为默认选择的CBC模式而且向量没有定义，那么向量会被定义为NULL。
                                如果选择了ECB模式或是其他的流密码算法，之前所说的逻辑都不成立。
    
    @param      dataIn          Data to encrypt or decrypt, length dataInLength 
                                bytes. 
    
    @param      dataInLength    Length of data to encrypt or decrypt.
    
    @param      dataOut         Result is written here. Allocated by caller. 
                                Encryption and decryption can be performed
                                "in-place", with the same buffer used for 
                                input and output. 
    
    @param      dataOutAvailable The size of the dataOut buffer in bytes.  
    
    @param      dataOutMoved    On successful return, the number of bytes
    				written to dataOut. If kCCBufferTooSmall is
				returned as a result of insufficient buffer
				space being provided, the required buffer space
				is returned here. 
        
    @result     kCCBufferTooSmall indicates insufficent space in the dataOut
                                buffer. In this case, the *dataOutMoved 
                                parameter will indicate the size of the buffer
                                needed to complete the operation. The 
                                operation can be retried with minimal runtime 
                                penalty. 
                kCCAlignmentError indicates that dataInLength was not properly 
                                aligned. This can only be returned for block 
                                ciphers, and then only when decrypting or when 
                                encrypting with block with padding disabled. 
                kCCDecodeError  Indicates improperly formatted ciphertext or
                                a "wrong key" error; occurs only during decrypt
                                operations. 
 */
    
CCCryptorStatus CCCrypt(
    CCOperation op,         /* kCCEncrypt, etc. */编码 or 解码
    CCAlgorithm alg,        /* kCCAlgorithmAES128, etc. */
    CCOptions options,      /* kCCOptionPKCS7Padding, etc. */
    const void *key,
    size_t keyLength,
    const void *iv,         /* optional initialization vector */
    const void *dataIn,     /* optional per op and alg */
    size_t dataInLength,
    void *dataOut,          /* data RETURNED here */
    size_t dataOutAvailable,
    size_t *dataOutMoved)
```
