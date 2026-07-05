// In-process receiver for the agent's hwa:// URL scheme. macOS delivers URL
// opens as a kAEGetURL Apple Event to the running application; this handler
// extracts the URI string and hands it to Go (hwaHandleURL, cgo export).
#import <Cocoa/Cocoa.h>
#include "_cgo_export.h"

@interface HWAURLHandler : NSObject
+ (HWAURLHandler *)sharedHandler;
- (void)handleGetURLEvent:(NSAppleEventDescriptor *)event
           withReplyEvent:(NSAppleEventDescriptor *)replyEvent;
@end

@implementation HWAURLHandler

+ (HWAURLHandler *)sharedHandler {
  static HWAURLHandler *shared = nil;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    shared = [[HWAURLHandler alloc] init];
  });
  return shared;
}

- (void)handleGetURLEvent:(NSAppleEventDescriptor *)event
           withReplyEvent:(NSAppleEventDescriptor *)replyEvent {
  (void)replyEvent;
  NSString *uri = [[event paramDescriptorForKeyword:keyDirectObject] stringValue];
  if (uri != nil) {
    hwaHandleURL((char *)[uri UTF8String]);
  }
}

@end

void hwaInstallURLHandler(void) {
  [[NSAppleEventManager sharedAppleEventManager]
      setEventHandler:[HWAURLHandler sharedHandler]
          andSelector:@selector(handleGetURLEvent:withReplyEvent:)
        forEventClass:kInternetEventClass
           andEventID:kAEGetURL];
}
