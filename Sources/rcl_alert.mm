#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

#include "rcl_alert.h"

#include <string>

namespace rcl
{

static std::string g_alert_last;

static UIWindow *alert_window(void)
{
    UIWindow *win = nil;
    for (UIScene *sc in [UIApplication sharedApplication].connectedScenes)
    {
        if (![sc isKindOfClass:[UIWindowScene class]])
        {
            continue;
        }
        UIWindowScene *ws = (UIWindowScene *)sc;
        for (UIWindow *w in ws.windows)
        {
            if (w.isKeyWindow)
            {
                win = w;
                break;
            }
        }
        if (!win && ws.windows.count > 0)
        {
            win = [ws.windows firstObject];
        }
        if (win)
        {
            break;
        }
    }
    return win;
}

void alert_show(const char *title, const char *message)
{
    NSString *t = title ? [NSString stringWithUTF8String:title] : @"Recoil";
    NSString *m = message ? [NSString stringWithUTF8String:message] : @"";
    const std::string key =
        std::string(title ? title : "Recoil") + "\n" + std::string(message ? message : "");
    @synchronized([UIApplication class])
    {
        if (g_alert_last == key)
        {
            return;
        }
        g_alert_last = key;
    }
    dispatch_async(dispatch_get_main_queue(), ^{
      UIWindow *win = alert_window();
      if (!win)
      {
          return;
      }
      UIViewController *root = win.rootViewController;
      if (!root)
      {
          return;
      }
      while (root.presentedViewController)
      {
          UIViewController *next = root.presentedViewController;
          if ([next isKindOfClass:[UIAlertController class]])
          {
              return;
          }
          root = next;
      }
      UIAlertController *a =
          [UIAlertController alertControllerWithTitle:t
                                              message:m
                                       preferredStyle:UIAlertControllerStyleAlert];
      NSMutableParagraphStyle *ps = [[NSMutableParagraphStyle alloc] init];
      ps.alignment = NSTextAlignmentLeft;
      NSDictionary *attrs = @{
          NSFontAttributeName : [UIFont monospacedSystemFontOfSize:12.0
                                                            weight:UIFontWeightRegular],
          NSParagraphStyleAttributeName : ps
      };
      NSAttributedString *body = [[NSAttributedString alloc] initWithString:m attributes:attrs];
      @try
      {
          [a setValue:body forKey:@"attributedMessage"];
      }
      @catch (NSException *e)
      {
      }
      [a addAction:[UIAlertAction actionWithTitle:@"OK"
                                            style:UIAlertActionStyleDefault
                                          handler:nil]];
      [a addAction:[UIAlertAction actionWithTitle:@"Копировать"
                                            style:UIAlertActionStyleDefault
                                          handler:^(UIAlertAction *act) {
                                            (void)act;
                                            [UIPasteboard generalPasteboard].string =
                                                [NSString stringWithFormat:@"%@\n%@", t, m];
                                          }]];
      [root presentViewController:a animated:YES completion:nil];
    });
}

} // namespace rcl
