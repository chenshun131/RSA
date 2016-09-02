//
//  ViewController.m
//  RSA_IOS_OpenSLL_Demo
//
//  Created by dfjty on 16/9/2.
//  Copyright © 2016年 chenshun. All rights reserved.
//

#import "ViewController.h"
#import "RSA.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    NSString *s = @"陈顺chenshunCHENSHUN123456..<>";
    RSA *rsa = [RSA new];
    NSString *encrypResult = [rsa encryptRSA:s];
    NSLog(@"result is %@", encrypResult);
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
