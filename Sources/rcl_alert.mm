#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

#include "rcl_alert.h"

namespace rcl {

void alert_show(const char *title, const char *message)
{
    NSString *t = title ? [NSString stringWithUTF8String:title] : @"Recoil";
    NSString *m = message ? [NSString stringWithUTF8String:message] : @"";
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *win = nil;
        for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
            UIWindowScene *ws = nil;
            if (![sc isKindOfClass:[UIWindowScene class]]) {
                continue;
            }
            ws = (UIWindowScene *)sc;
            for (UIWindow *w in ws.windows) {
                if (w.isKeyWindow) {
                    win = w;
                    break;
                }
            }
            if (!win && ws.windows.count > 0) {
                win = [ws.windows firstObject];
            }
            if (win) {
                break;
            }
        }
        if (!win) {
            return;
        }
        UIViewController *root = win.rootViewController;
        if (!root) {
            return;
        }
        while (root.presentedViewController) {
            root = root.presentedViewController;
        }
        UIAlertController *a = [UIAlertController alertControllerWithTitle:t
                                                                  message:m
                                                           preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [root presentViewController:a animated:YES completion:nil];
    });
}

}

