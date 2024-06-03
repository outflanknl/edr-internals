#include <NetworkExtension/NetworkExtension.h>
#include <OSLog/OSLog.h>

#include "config.h"
#include "util.h"
#include "ne_json.hpp"

os_log_t logHandle = nil;

@interface FilterDataProvider : NEFilterDataProvider

@end

@implementation FilterDataProvider

-(void)startFilterWithCompletionHandler:(void (^)(NSError *error))completionHandler {
    NENetworkRule* networkRule = nil;
    NEFilterRule* filterRule = nil;
    NEFilterSettings* filterSettings = nil;

    os_log_debug(logHandle, "%s", __PRETTY_FUNCTION__);

    networkRule = [[NENetworkRule alloc] initWithRemoteNetwork:nil remotePrefix:0 localNetwork:nil localPrefix:0 protocol:NENetworkRuleProtocolAny direction:NETrafficDirectionAny];
    filterRule = [[NEFilterRule alloc] initWithNetworkRule:networkRule action:NEFilterActionFilterData];
    filterSettings = [[NEFilterSettings alloc] initWithRules:@[filterRule] defaultAction:NEFilterActionAllow];

    [self applySettings:filterSettings completionHandler:^(NSError * _Nullable error) {
        if (error != nil) {
            os_log_error(logHandle, "ERROR: Failed to apply filter settings: %@", error.localizedDescription);
        }

        completionHandler(error);
    }];
}

-(void)stopFilterWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler {
    completionHandler();
    return;
}

-(NEFilterNewFlowVerdict *)handleNewFlow:(NEFilterFlow *)flow {
    @try {
        auto flow_arr = json{ (NEFilterSocketFlow*)flow };
        for (auto it : flow_arr) {
            const std::string flow_fmt = it.dump(JSON_INDENT);
            os_log(logHandle, "%{public}s", flow_fmt.c_str());
        }
    } @catch (NSException *exception) {
        os_log_error(logHandle, "ERROR: %@", exception);
    } @finally {
        return [NEFilterNewFlowVerdict allowVerdict];
    }
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        logHandle = os_log_create("nedump", "extension");

        os_log(logHandle, "Starting extension...");
        [NEProvider startSystemExtensionMode];
        os_log(logHandle, "Extension started!");
    }

    dispatch_main();

    return 0;
    
    (void)argc;
    (void)argv;
}

@end
