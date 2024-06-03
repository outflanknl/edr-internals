#pragma once

#define ACTION_DEACTIVATE 0
#define ACTION_ACTIVATE 1

typedef void(^replyBlockType)(BOOL);

@interface OSLogEventLiveStream : NSObject

- (void)activate;
- (void)invalidate;
- (void)setFilterPredicate:(NSPredicate*)predicate;
- (void)setDroppedEventHandler:(void(^)(id))callback;
- (void)setInvalidationHandler:(void(^)(int, id))callback;
- (void)setEventHandler:(void(^)(id))callback;

@property(nonatomic) unsigned long long flags;

@end

@interface OSLogEventProxy : NSObject

@property(readonly, nonatomic) NSString* process;
@property(readonly, nonatomic) int processIdentifier;
@property(readonly, nonatomic) NSString* processImagePath;

@property(readonly, nonatomic) NSString* sender;
@property(readonly, nonatomic) NSString* senderImagePath;

@property(readonly, nonatomic) NSString* category;
@property(readonly, nonatomic) NSString* subsystem;

@property(readonly, nonatomic) NSDate* date;

@property(readonly, nonatomic) NSString* composedMessage;

@end

@interface LogMonitor : NSObject

@property(nonatomic, retain, nullable)OSLogEventLiveStream* liveStream;

-(BOOL)start:(NSPredicate*)predicate level:(NSUInteger)level eventHandler:(void(^)(OSLogEventProxy*))eventHandler;

-(void)stop;

@end

@interface Extension : NSObject <OSSystemExtensionRequestDelegate>

@property(nonatomic, copy)replyBlockType replyBlock;

-(void)toggleExtension:(NSUInteger)action reply:(void (^)(BOOL))reply;

-(void)startNetworkExtension:(void (^)(BOOL))reply;

@end
