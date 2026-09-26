#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>

@interface AppDelegate : NSObject <NSApplicationDelegate, WKNavigationDelegate, WKUIDelegate, WKDownloadDelegate>
@property NSWindow *window;
@property WKWebView *webView;
@property NSTask *task;
@property NSInteger retries;
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    [self makeMenu];
    [self makeWindow];
    [self startHarness];
    [self performSelector:@selector(loadHarness) withObject:nil afterDelay:0.8];
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender { return YES; }

- (void)applicationWillTerminate:(NSNotification *)notification {
    [NSObject cancelPreviousPerformRequestsWithTarget:self];
    if (self.task.running) {
        [self.task terminate];
        [self.task waitUntilExit];
    }
}

- (void)makeMenu {
    NSMenu *menu = [[NSMenu alloc] init];
    NSMenuItem *appItem = [[NSMenuItem alloc] init];
    [menu addItem:appItem];
    NSMenu *appMenu = [[NSMenu alloc] initWithTitle:@"Agent B"];
    [appMenu addItemWithTitle:@"About Agent B" action:@selector(orderFrontStandardAboutPanel:) keyEquivalent:@""];
    [appMenu addItem:[NSMenuItem separatorItem]];
    [appMenu addItemWithTitle:@"Quit Agent B" action:@selector(terminate:) keyEquivalent:@"q"];
    appItem.submenu = appMenu;

    NSMenuItem *editItem = [[NSMenuItem alloc] init];
    [menu addItem:editItem];
    NSMenu *editMenu = [[NSMenu alloc] initWithTitle:@"Edit"];
    [editMenu addItemWithTitle:@"Undo" action:@selector(undo:) keyEquivalent:@"z"];
    NSMenuItem *redo = [editMenu addItemWithTitle:@"Redo" action:@selector(redo:) keyEquivalent:@"Z"];
    redo.keyEquivalentModifierMask = NSEventModifierFlagCommand | NSEventModifierFlagShift;
    [editMenu addItem:[NSMenuItem separatorItem]];
    [editMenu addItemWithTitle:@"Cut" action:@selector(cut:) keyEquivalent:@"x"];
    [editMenu addItemWithTitle:@"Copy" action:@selector(copy:) keyEquivalent:@"c"];
    [editMenu addItemWithTitle:@"Paste" action:@selector(paste:) keyEquivalent:@"v"];
    [editMenu addItemWithTitle:@"Select All" action:@selector(selectAll:) keyEquivalent:@"a"];
    editItem.submenu = editMenu;
    NSApp.mainMenu = menu;
}

- (void)makeWindow {
    WKWebViewConfiguration *configuration = [[WKWebViewConfiguration alloc] init];
    self.webView = [[WKWebView alloc] initWithFrame:NSZeroRect configuration:configuration];
    self.webView.navigationDelegate = self;
    self.webView.UIDelegate = self;
    self.window = [[NSWindow alloc]
        initWithContentRect:NSMakeRect(0, 0, 1240, 820)
        styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable
        backing:NSBackingStoreBuffered
        defer:NO];
    self.window.title = @"Agent B";
    self.window.titlebarAppearsTransparent = NO;
    self.window.minSize = NSMakeSize(840, 600);
    self.window.contentView = self.webView;
    [self.window center];
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
    [self.webView loadHTMLString:@"<body style='background:#0a0c0f;color:#eef1f5;font:15px -apple-system;display:grid;place-items:center;height:100vh;margin:0'>Starting Agent B…</body>" baseURL:nil];
}

- (void)startHarness {
    NSURL *resources = NSBundle.mainBundle.resourceURL;
    NSURL *harness = [resources URLByAppendingPathComponent:@"harness"];
    NSURL *support = [[[NSFileManager defaultManager] URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask].firstObject URLByAppendingPathComponent:@"Agent B"];
    [[NSFileManager defaultManager] createDirectoryAtURL:support withIntermediateDirectories:YES attributes:nil error:nil];

    self.task = [[NSTask alloc] init];
    NSString *python = [resources URLByAppendingPathComponent:@"python/bin/python3"].path;
    if (![[NSFileManager defaultManager] isExecutableFileAtPath:python]) {
        [self showError:@"Agent B's bundled Python runtime is missing. Download a fresh copy of the app."];
        return;
    }
    self.task.executableURL = [NSURL fileURLWithPath:python];
    self.task.arguments = @[@"-E", @"-s", @"-B", @"-m", @"agent_b_harness.server", @"--no-browser", @"--port", @"4310"];
    self.task.currentDirectoryURL = harness;
    NSDictionary *parentEnvironment = NSProcessInfo.processInfo.environment;
    NSMutableDictionary *environment = [@{
        @"HOME": NSHomeDirectory(),
        @"PATH": @"/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        @"LANG": @"C.UTF-8",
        @"LC_ALL": @"C.UTF-8",
    } mutableCopy];
    NSString *temporaryDirectory = parentEnvironment[@"TMPDIR"];
    if (temporaryDirectory.length) environment[@"TMPDIR"] = temporaryDirectory;
    environment[@"AGENT_B_DATA_DIR"] = support.path;
    environment[@"SSL_CERT_FILE"] = [resources URLByAppendingPathComponent:@"python/lib/python3.12/site-packages/pip/_vendor/certifi/cacert.pem"].path;
    self.task.environment = environment;

    NSURL *logs = [[[[NSFileManager defaultManager] URLsForDirectory:NSLibraryDirectory inDomains:NSUserDomainMask].firstObject URLByAppendingPathComponent:@"Logs"] URLByAppendingPathComponent:@"Agent B.log"];
    [[NSFileManager defaultManager] createFileAtPath:logs.path contents:nil attributes:nil];
    NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:logs.path];
    [handle seekToEndOfFile];
    self.task.standardOutput = handle;
    self.task.standardError = handle;
    NSError *error = nil;
    if (![self.task launchAndReturnError:&error]) {
        [self showError:[NSString stringWithFormat:@"Could not start Agent B: %@", error.localizedDescription]];
    }
}

- (void)loadHarness {
    [self.webView loadRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:@"http://127.0.0.1:4310/"] cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:2.0]];
}

- (void)webView:(WKWebView *)webView didFailProvisionalNavigation:(WKNavigation *)navigation withError:(NSError *)error {
    self.retries += 1;
    if (self.retries < 30) {
        [self performSelector:@selector(loadHarness) withObject:nil afterDelay:0.4];
        return;
    }
    [self showError:@"Agent B did not start. See ~/Library/Logs/Agent B.log"];
}

- (void)webView:(WKWebView *)webView decidePolicyForNavigationAction:(WKNavigationAction *)navigationAction decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler {
    NSURL *url = navigationAction.request.URL;
    NSString *scheme = url.scheme.lowercaseString;
    NSString *host = url.host.lowercaseString;
    BOOL localHarness = ([host isEqualToString:@"127.0.0.1"] || [host isEqualToString:@"localhost"])
        && (url.port == nil || url.port.integerValue == 4310);
    if (url == nil || [scheme isEqualToString:@"about"] || localHarness) {
        if (localHarness && navigationAction.shouldPerformDownload) {
            decisionHandler(WKNavigationActionPolicyDownload);
            return;
        }
        decisionHandler(WKNavigationActionPolicyAllow);
        return;
    }
    if ([scheme isEqualToString:@"http"] || [scheme isEqualToString:@"https"]) {
        [[NSWorkspace sharedWorkspace] openURL:url];
    }
    decisionHandler(WKNavigationActionPolicyCancel);
}

- (void)webView:(WKWebView *)webView runOpenPanelWithParameters:(WKOpenPanelParameters *)parameters initiatedByFrame:(WKFrameInfo *)frame completionHandler:(void (^)(NSArray<NSURL *> *))completionHandler {
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    panel.canChooseFiles = YES;
    panel.canChooseDirectories = NO;
    panel.allowsMultipleSelection = parameters.allowsMultipleSelection;
    [panel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse result) {
        completionHandler(result == NSModalResponseOK ? panel.URLs : nil);
    }];
}

- (void)webView:(WKWebView *)webView decidePolicyForNavigationResponse:(WKNavigationResponse *)response decisionHandler:(void (^)(WKNavigationResponsePolicy))decisionHandler {
    NSHTTPURLResponse *http = (NSHTTPURLResponse *)response.response;
    NSString *disposition = [http isKindOfClass:[NSHTTPURLResponse class]] ? [http valueForHTTPHeaderField:@"Content-Disposition"] : nil;
    decisionHandler([disposition.lowercaseString hasPrefix:@"attachment"] ? WKNavigationResponsePolicyDownload : WKNavigationResponsePolicyAllow);
}

- (void)webView:(WKWebView *)webView navigationAction:(WKNavigationAction *)action didBecomeDownload:(WKDownload *)download { download.delegate = self; }
- (void)webView:(WKWebView *)webView navigationResponse:(WKNavigationResponse *)response didBecomeDownload:(WKDownload *)download { download.delegate = self; }

- (void)download:(WKDownload *)download decideDestinationUsingResponse:(NSURLResponse *)response suggestedFilename:(NSString *)suggestedFilename completionHandler:(void (^)(NSURL *))completionHandler {
    NSSavePanel *panel = [NSSavePanel savePanel];
    panel.nameFieldStringValue = suggestedFilename.lastPathComponent;
    [panel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse result) {
        completionHandler(result == NSModalResponseOK ? panel.URL : nil);
    }];
}

- (void)download:(WKDownload *)download didFailWithError:(NSError *)error resumeData:(NSData *)resumeData {
    if (error.code == NSURLErrorCancelled) return;
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = @"Download could not finish";
    alert.informativeText = error.localizedDescription;
    [alert beginSheetModalForWindow:self.window completionHandler:nil];
}

// WKWebView suppresses JS alert()/confirm()/prompt() unless the host app
// implements these WKUIDelegate panels. Without them confirm() returns false,
// which silently blocked the Remove connection button and hid every alert().
- (void)webView:(WKWebView *)webView
        runJavaScriptAlertPanelWithMessage:(NSString *)message
        initiatedByFrame:(WKFrameInfo *)frame
        completionHandler:(void (^)(void))completionHandler {
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = @"Agent B";
    alert.informativeText = message ?: @"";
    [alert addButtonWithTitle:@"OK"];
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        completionHandler();
    }];
}

- (void)webView:(WKWebView *)webView
        runJavaScriptConfirmPanelWithMessage:(NSString *)message
        initiatedByFrame:(WKFrameInfo *)frame
        completionHandler:(void (^)(BOOL))completionHandler {
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = @"Agent B";
    alert.informativeText = message ?: @"";
    [alert addButtonWithTitle:@"OK"];
    [alert addButtonWithTitle:@"Cancel"];
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        completionHandler(response == NSAlertFirstButtonReturn);
    }];
}

- (void)webView:(WKWebView *)webView
        runJavaScriptTextInputPanelWithPrompt:(NSString *)prompt
        defaultText:(NSString *)defaultText
        initiatedByFrame:(WKFrameInfo *)frame
        completionHandler:(void (^)(NSString * _Nullable))completionHandler {
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = prompt ?: @"";
    [alert addButtonWithTitle:@"OK"];
    [alert addButtonWithTitle:@"Cancel"];
    NSTextField *input = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, 320, 24)];
    input.stringValue = defaultText ?: @"";
    alert.accessoryView = input;
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        completionHandler(response == NSAlertFirstButtonReturn ? input.stringValue : nil);
    }];
}

- (void)showError:(NSString *)text {
    NSString *html = [NSString stringWithFormat:@"<body style='background:#0a0c0f;color:#ff8b91;font:15px -apple-system;padding:40px'>%@</body>", text];
    [self.webView loadHTMLString:html baseURL:nil];
}

@end

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSApplication *app = NSApplication.sharedApplication;
        AppDelegate *delegate = [[AppDelegate alloc] init];
        app.delegate = delegate;
        [app setActivationPolicy:NSApplicationActivationPolicyRegular];
        [app run];
    }
    return 0;
}
