//
//  RSA.h
//  saccounts_ios_sdk_sso_framework
//
//  Created by BabyDuncan on 13-9-5.
//  Copyright (c) 2013年 SOHU.COM. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RSA : NSObject

/**
 * 通过证书加密数据，产生的加密数据可以 Java 解密
 */
- (NSString *)encryptRSA:(NSString *)plainTextString;

- (NSString *)decryptRSA:(NSString *)cipherString key:(SecKeyRef)privateKey;

@end
