#include <NetworkExtension/NetworkExtension.h>
#include <SystemExtensions/SystemExtensions.h>

#include "nedump.h"

@implementation Extension

-(void)toggleExtension:(NSUInteger)action reply:(void (^)(BOOL))reply
{
    self.replyBlock = reply;
    
    OSSystemExtensionRequest* request = nil;
    if (action == ACTION_ACTIVATE) {
        NSLog(@"Activating extension...");
        request = [OSSystemExtensionRequest activationRequestForExtension:@EXT_BUNDLE_ID queue:dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0)];
    }
    else {
        NSLog(@"Deactivating extension...");
        request = [OSSystemExtensionRequest deactivationRequestForExtension:@EXT_BUNDLE_ID queue:dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0)];
    }

    if (request == nil) {
        NSLog(@"ERROR: Failed to create request for extension");
        return;
    }

    request.delegate = self;

    [OSSystemExtensionManager.sharedManager submitRequest:request];
}

-(void)startNetworkExtension:(void (^)(BOOL))reply
{
    __block NEFilterProviderConfiguration* config =  nil;

    NSLog(@"Starting network extension...");
    [NEFilterManager.sharedManager loadFromPreferencesWithCompletionHandler:^(NSError* _Nullable error) {
        if (error != nil) {
            NSLog(@"ERROR: 'loadFromPreferencesWithCompletionHandler' failed with %@", error);
            reply(NO);

            return;
        }

        NSLog(@"Activating network extension...");

        config = [[NEFilterProviderConfiguration alloc] init];
        config.filterPackets = NO;
        config.filterSockets = YES;
        NEFilterManager.sharedManager.providerConfiguration = config;
        NEFilterManager.sharedManager.localizedDescription = @"NEDump";
        NEFilterManager.sharedManager.enabled = YES;

        [NEFilterManager.sharedManager saveToPreferencesWithCompletionHandler:^(NSError* _Nullable error) {
            if (error != nil) {
                NSLog(@"ERROR: 'saveToPreferencesWithCompletionHandler' failed with %@", error);
                reply(NO);

                return;
            }

            reply(YES);
        }];
    }];

    return;
}

#pragma mark -
#pragma mark OSSystemExtensionRequest delegate methods

-(OSSystemExtensionReplacementAction)request:(nonnull OSSystemExtensionRequest*)request actionForReplacingExtension:(nonnull OSSystemExtensionProperties*)existing withExtension:(nonnull OSSystemExtensionProperties*)ext
{
    NSLog(@"Method '%s' invoked with %@, %@ -> %@", __PRETTY_FUNCTION__, request.identifier, existing.bundleShortVersion, ext.bundleShortVersion);
    return OSSystemExtensionReplacementActionReplace;
}


-(void)request:(nonnull OSSystemExtensionRequest*)request didFailWithError:(nonnull NSError*)error
{
    NSLog(@"ERROR: Method '%s' invoked with %@, %@", __PRETTY_FUNCTION__, request, error);
    self.replyBlock(NO);

    return;
}

-(void)request:(nonnull OSSystemExtensionRequest*)request didFinishWithResult:(OSSystemExtensionRequestResult)result {
    NSLog(@"Method '%s' invoked with %@, %ld", __PRETTY_FUNCTION__, request, (long)result);

    if (result != OSSystemExtensionRequestCompleted) {
        NSLog(@"ERROR: Result %ld is an unexpected result for system extension request", (long)result);
        self.replyBlock(NO);

        return;
    }
    
    self.replyBlock(YES);
}

-(void)requestNeedsUserApproval:(nonnull OSSystemExtensionRequest*)request {
    NSLog(@"Method '%s' invoked with %@", __PRETTY_FUNCTION__, request);
}

@end

@implementation LogMonitor

-(BOOL)start:(NSPredicate*)predicate level:(NSUInteger)level eventHandler:(void(^)(OSLogEventProxy*))eventHandler
{
    [[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/LoggingSupport.framework"] load];

    Class LiveStream = NSClassFromString(@"OSLogEventLiveStream");
    if (LiveStream == nil)
        return NO;

    self.liveStream = [[LiveStream alloc] init];
    if (self.liveStream == nil)
        return NO;

    if ([self.liveStream respondsToSelector:NSSelectorFromString(@"setFilterPredicate:")] != YES)
        return NO;

    if (predicate != nil)
        [self.liveStream setFilterPredicate:predicate];

    if ([self.liveStream respondsToSelector:NSSelectorFromString(@"setInvalidationHandler:")] != YES)
        return NO;

    [self.liveStream setInvalidationHandler:^void (int reason, id streamPosition) {}];

    if ([self.liveStream respondsToSelector:NSSelectorFromString(@"setDroppedEventHandler:")] != YES)
        return NO;

    [self.liveStream setDroppedEventHandler:^void (id droppedMessage) {}];

    if ([self.liveStream respondsToSelector:NSSelectorFromString(@"setEventHandler:")] != YES)
        return NO;

    [self.liveStream setEventHandler:eventHandler];

    if ([self.liveStream respondsToSelector:NSSelectorFromString(@"activate")] != YES)
        return NO;
    
    if ([self.liveStream respondsToSelector:NSSelectorFromString(@"setFlags:")] != YES)
        return NO;

    [self.liveStream setFlags:level];
    [self.liveStream activate];

    return YES;
}

-(void)stop
{
    if ([self.liveStream respondsToSelector:NSSelectorFromString(@"invalidate")] == YES) {
        if (self.liveStream != nil)
            [self.liveStream invalidate];
    }
}

@end

int main(int argc, const char* argv[]) {
    NSPredicate* predicate = [NSPredicate predicateWithFormat:@"subsystem='nedump'"];
    LogMonitor* logMonitor = [[LogMonitor alloc] init];
    Extension* ext = [[Extension alloc] init];

    if (logMonitor == nil || ext == nil) {
        NSLog(@"ERROR: Failed to initialize log monitor or extension");
        return false;
    }

    [logMonitor start:predicate level:0 eventHandler:^(OSLogEventProxy* event) {
        printf("%s,\n", event.composedMessage.UTF8String);
    }];

    [ext toggleExtension:ACTION_ACTIVATE reply:^(BOOL toggled) {
        if (toggled == YES) {
            [ext startNetworkExtension:^(BOOL started) {
                if (started == YES) {
                    NSLog(@"Network extension started successfully");
                }
                else {
                    NSLog(@"ERROR: Failed to start network extension");
                }
            }];
        }
    }];

    [[NSRunLoop currentRunLoop] run];

    return 0;
}
